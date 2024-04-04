
from __future__ import annotations

import httpx
import json
from datetime import datetime
import uuid
from opentelemetry.sdk.resources import SERVICE_NAME, Resource

from opentelemetry.sdk.resources import Resource
import logging

from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from presidio_analyzer import AnalyzerEngine
import boto3
from presidio_analyzer.nlp_engine import NlpEngineProvider
import time
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.metrics import get_meter
from detoxify import Detoxify


DLP_CONFIG_PATH = "dlp/dlp.json"
ABUSE_CONFIG_PATH = "abuse/abuse.json"
API_KEYS_PATH = "api-keys/{0}/key.json"
AIGOV_SERVICE_NAME = "aigov"
OTEL_LOGS_PATH = "/v1/logs"
OTEL_METRICS_PATH = "/v1/metrics"


class ConfigProvider:
    def __init__(self, aws_session, config_bucket, collector_endpoint):
        self._config_bucket = config_bucket
        self._collector_endpoint = collector_endpoint
        if aws_session is None:
            aws_session = boto3.Session()
        self.s3_client = aws_session.resource('s3')
        self.user = aws_session.client(
            'sts').get_caller_identity().get('Arn').split(":")[5]

    def read_file_from_s3(self, path):
        try:
            obj = self.s3_client.Object(self._config_bucket, path).get()
            data = obj['Body'].read().decode('utf-8')
            return json.loads(data)
        except Exception as e:
            raise Exception("Error reading the config file from S3: "
                            + str(e) + ". Please check if you have the right permissions.")

    def get_dlp_config(self):
        dlp_config = self.read_file_from_s3(DLP_CONFIG_PATH)["dlp"]
        return dlp_config

    def get_abuse_config(self):
        abuse_config = self.read_file_from_s3(ABUSE_CONFIG_PATH)
        return abuse_config

    def get_api_key(self, provider):
        path = API_KEYS_PATH.format(provider)
        api_key = self.read_file_from_s3(path)["key"]
        return api_key

    def get_user(self):
        return self.user

    def get_org(self):
        return "Acme Inc."

    def get_collector_endpoint(self):
        return self._collector_endpoint


class DLPBlocker:
    def __init__(self, config_provider):
        self.config_provider = config_provider
        configuration = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
        provider = NlpEngineProvider(nlp_configuration=configuration)
        nlp_engine = provider.create_engine()
        self.block_analyzer = AnalyzerEngine(nlp_engine=nlp_engine)

    def check(self, text):
        dlp_config = self.config_provider.get_dlp_config()
        self.block_entities = []
        for z in dlp_config['preset']:
            if z['status'] == "Block":
                self.block_entities.append(z['name'])
        if not self.block_entities:
            return None
        block_results = self.block_analyzer.analyze(
            text=text, entities=self.block_entities, language='en')
        return block_results


class AbusiveLanguageDetector:
    def __init__(self, config_provider):
        self._model = Detoxify("original")
        self.config_provider = config_provider

    def check(self, text):
        abuse_config = self.config_provider.get_abuse_config()
        preds = self._model.predict(text)
        output = []
        for k in preds:
            if k in abuse_config and abuse_config[k]:
                if preds[k] > 0.5:
                    output.append(k)
        return output


class Logger:
    def __init__(self, config_provider):
        resource = Resource(attributes={SERVICE_NAME: AIGOV_SERVICE_NAME})
        self._logger = logging.getLogger(AIGOV_SERVICE_NAME)
        self._logger.propagate = False
        p_logger = logging.getLogger("presidio-analyzer")
        p_logger.propagate = False

        exporter = OTLPLogExporter(
            endpoint=config_provider.get_collector_endpoint() + OTEL_LOGS_PATH)
        logger_provider = LoggerProvider(resource=resource)
        logger_provider.add_log_record_processor(
            BatchLogRecordProcessor(exporter))
        handler = LoggingHandler(
            level=logging.DEBUG, logger_provider=logger_provider)
        self._logger.addHandler(handler)
        self._logger.setLevel(logging.DEBUG)

    def log(self, data):
        print("in logger")
        self._logger.debug(json.dumps(data))


class Metrics:
    def __init__(self, config_provider) -> None:
        resource = Resource(attributes={SERVICE_NAME: AIGOV_SERVICE_NAME})
        otlp_exporter = OTLPMetricExporter(
            endpoint=config_provider.get_collector_endpoint()+OTEL_METRICS_PATH)
        reader = PeriodicExportingMetricReader(
            otlp_exporter, export_interval_millis=1000)
        provider = MeterProvider(metric_readers=[reader], resource=resource)
        metrics.set_meter_provider(provider)
        meter = get_meter("obex-counts")
        self.total_counter = meter.create_counter("total")

    def record_request(self):
        self.total_counter.add(1)


class Wrapper:
    def __init__(self, *, config_bucket, collector_endpoint, aws_session=None):
        self.config_provider = ConfigProvider(
            aws_session, config_bucket, collector_endpoint)
        self.logger = Logger(self.config_provider)
        self.metrics = Metrics(self.config_provider)
        self.dlp_blocker = DLPBlocker(self.config_provider)
        self.abuse_checker = AbusiveLanguageDetector(self.config_provider)

    def get_provider(self, url):
        if "openai" in url.__str__():
            return "openai"
        elif "anthropic" in url.__str__():
            return "anthropic"
        return "unknown"

    def get_model(self, request_body):
        if '"model": "claude-3' in request_body:
            return "Claude-3"
        if '"model": "gpt-3.5-turbo' in request_body:
            return "GPT-3.5-turbo"
        return "unknown"

    def build_audit_object(self, request, request_body, dlp_check=[], abuse_check_request=[], abuse_check_response=[]):
        data = {}
        data["type"] = "ai_call_event"
        data["uid"] = str(uuid.uuid4())
        data["url"] = str(request.url)
        data["timestamp"] = str(datetime.now())
        data["prompt"] = request_body
        data["user"] = self.config_provider.get_user()
        data["org"] = self.config_provider.get_org()
        data["provider"] = self.get_provider(request.url)
        data["model"] = self.get_model(request_body)
        data["dlp"] = str(dlp_check)
        data["abuse_request"] = str(abuse_check_request)
        data["abuse_response"] = str(abuse_check_response)
        data["status"] = "Success"
        if dlp_check:
            data["status"] = "Blocked [DLP]"
        if abuse_check_request:
            data["status"] = "Blocked [Abusive request]"
        if abuse_check_response:
            data["status"] = "Blocked [Abusive response]"
        return data

    def set_auth_header(self, request):
        provider = self.get_provider(request.url)
        if provider == "openai":
            request.headers['authorization'] = "Bearer " + \
                self.config_provider.get_api_key("openai")
        if provider == "anthropic":
            request.headers['x-api-key'] = self.config_provider.get_api_key(
                "anthropic")

    def get_response_content(self, response):
        jr = json.loads(response.text)
        return jr['choices'][0]['message']['content']

    def generate_error(self, request, message):
        return httpx.Response(status_code=403, request=request, json='{"msg": "' + message + '"}')

    def protect(self, func):

        oldsend = httpx.Client.send

        def new_send(*args, **kwargs):
            request = args[1]
            request_body = request.read().decode("utf-8")

            provider = self.get_provider(request.url)
            self.metrics.record_request()
            dlp_check = self.dlp_blocker.check(request_body)
            if dlp_check:
                audit_data = self.build_audit_object(
                    request, request_body, dlp_check)
                self.logger.log(audit_data)
                return self.generate_error(request, "Request blocked for violating DLP rules: " + str(dlp_check))

            abuse_check_request = self.abuse_checker.check(request_body)
            if abuse_check_request:
                audit_data = self.build_audit_object(
                    request, request_body, dlp_check, abuse_check_request)
                self.logger.log(audit_data)
                return self.generate_error(request, "Request blocked for violating abusive content rules: " + str(abuse_check_request))

            self.set_auth_header(request)
            response = oldsend(*args, **kwargs)

            response_content = self.get_response_content(response)
            abuse_check_response = self.abuse_checker.check(response_content)
            if abuse_check_response:
                audit_data = self.build_audit_object(
                    request, request_body, dlp_check, abuse_check_request, abuse_check_response)
                self.logger.log(audit_data)
                return self.generate_error(request, "Request blocked for violating abusive content rules: " + str(abuse_check_response))

            audit_data = self.build_audit_object(
                request, request_body, dlp_check, abuse_check_request, abuse_check_response)
            self.logger.log(audit_data)

            return response

        def wrapper(*args, **kwargs):
            httpx.Client.send = new_send
            z = func(*args, **kwargs)
            httpx.Client.send = oldsend
            return z

        return wrapper
