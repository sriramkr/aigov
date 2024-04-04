# AIGov
This is a simple but extensible platform for AI Governance, designed to explain 
various concepts related to AI Governance. This is intended to be a companion
piece to the articles around AI Governance in my blog.

## What we'll do
At a high level, the idea is to build mechanisms that provide us with visibility and control when interacting with AI systems, as detailed in my blog. We'll take a specific example here, of interacting with OpenAI, an external AI vendor. Through this exercise we'll show that we can instrument mechanisms to get 
access control, auditability, data loss prevention (DLP), abusive data filtering, and anomaly detection. We want to accomplish all this with the simplest design possible, and yet have it be amenable for extensions in the future.


## Before starting
All the scripts here are designed to work with AWS and assume that the environment
has valid AWS credentials. If you haven't set up AWS CLI access already, do so following
instructions [here](https://docs.aws.amazon.com/cli/). Ensure that the user/principal 
has atleast full S3 access.

## Getting started
Create a new S3 bucket that will serve as our controller bucket. We'll use the name
`aigov-test` here, but replace this with whatever name you prefer. Similarly, we'll use
us-east-2 as the region, but this can be swapped for any AWS region.
You can do this from the CLI as follows:

``` aws s3api create-bucket --bucket aigov-test --region us-east-2``` 

The `base_configs` directory contains a set of configs that will serve as a starting point. One thing that this directory does not contain is a an OpenAI API key. Let's install that by running the following command (replace OPENAI_API_KEY with the actual key of course).

``` echo "{'key': 'OPENAI_API_KEY'}" > base_configs/api-keys/openai/key.json``` 

Initialize the bucket we created in step 1 with the base configs by running this.

```aws s3 cp -r base_configs/ s3://aigov-test```

Next let's setup a Python virtual environment. 

```python -m venv venv```

Install the required dependencies by running the following command.

```pip install -r requirements.txt```

We will use AWS CloudWatch for audit logs and metrics. CloudWatch does not need any setup
on top of creating the AWS account. But in case you need to configure something, you can set things up [here](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/GettingSetup.html).
At this point you should have the controller and environment set up.

## Exploring the example
Now we are ready to run the example. First, let's run the OpenTelemetry collector. To do this, go to the otel-collector directory.

```cd otel-collector```

Build the Docker image in the directory, after filling out the AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in `Dockerfile`.

```docker build -t otelcol .```

Run the Docker image, exposing port `4318` the standard HTTP port for OpenTelemetry.

```docker run -p 4318:4318 otelcol```

Finally we are ready  to run our example.

```cd ../example; python example.py```

## Playing around
The example shows the basic features we built:
1. Access Control - The API key is not stored in the example  - rather it is obtained 
by the wrapper, leveraging the access credentials of the envrionment. In other words,
unless the calling code has access to this API key, it cannot access it.
2. Audit Logs - The wrapper sends audit logs of all failed and successful calls, which
are then handled by the Open Telemetry collector. If you provided AWS creds in the Dockerfile, these should land up in CloudWatch logs in the corresponding AWS account.
3. DLP - DLP settings are configured in the dlp/dlp.json file in the bucket. Feel free to play around with them. Specifically, PII such as phone numbers, emails, etc. can be blocked, or permitted.
4. Abuse Protection - Abusive prompts and responses will be blocked. For instance, saying 'shut up' in the prompt will lead it to being blocked.

