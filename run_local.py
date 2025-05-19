import os
os.environ["FAIL_DNS_LOG_BUCKET"] = "cr-resolver-test"
import json
import lambda_function

with open('local_event.json') as f:
    event = json.load(f)

resp = lambda_function.lambda_handler(event, None)
print(json.dumps(resp, indent=2))
