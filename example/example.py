import sys
sys.path.append('../')
import wrapper.aigov as aigov
import openai
import boto3
import anthropic


openai_client = openai.OpenAI(api_key="sk-test")

session = boto3.Session()

OTEL_COLLECTOR_ENDPOINT = "http://localhost:4318"
wrapper = aigov.Wrapper(aws_session=session, config_bucket="obex-config-dev", collector_endpoint=OTEL_COLLECTOR_ENDPOINT)

@wrapper.protect
def call_openai(message):
	try:
		completion = openai_client.chat.completions.create(
			model="gpt-3.5-turbo",
			messages=[
			{"role": "system", "content": "You are a geography expert."},
			{"role": "user", "content": message}
			])
		return completion.choices[0].message.content
	except Exception as e:
		return "OpenAI API call failed with error: " + str(e)

message = "Which country is lutefisk from?"
message2 = "Here is a phone number: 732 516 8823. Which country is it from?"

print(call_openai(message))
print(call_openai(message2))

