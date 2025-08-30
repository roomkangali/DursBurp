# DursBurp - AI-Powered Security Analysis for Burp Suite
#
# Author: Kang Ali
# Version: 1.0.0
# GitHub: https://github.com/roomkangali/DursBurp
#
# This module handles the processing of the prompt template.

from java.io import PrintWriter

class PromptHandler:
    def __init__(self, callbacks):
        self.stdout = PrintWriter(callbacks.getStdout(), True) if hasattr(callbacks, 'getStdout') else None

    def process_prompt(self, prompt, request_bytes, request_info, response, helpers, max_size):
        try:
            # Extract request/response data
            url = str(request_info.getUrl())
            method = request_info.getMethod()
            request_headers = "\n".join([h for h in request_info.getHeaders()])
            body_offset = request_info.getBodyOffset()
            request_body = helpers.bytesToString(request_bytes[body_offset:])
            response_info = helpers.analyzeResponse(response)
            response_headers = "\n".join([h for h in response_info.getHeaders()])
            response_body = helpers.bytesToString(response[response_info.getBodyOffset():])
            
            # Process prompt with placeholders
            is_truncated = False
            if len(prompt) > max_size:
                prompt = prompt[:max_size]
                is_truncated = True
            prompt = prompt.replace("{URL}", url)
            prompt = prompt.replace("{METHOD}", method)
            prompt = prompt.replace("{REQUEST_HEADERS}", request_headers)
            prompt = prompt.replace("{REQUEST_BODY}", request_body)
            prompt = prompt.replace("{RESPONSE_HEADERS}", response_headers)
            prompt = prompt.replace("{RESPONSE_BODY}", response_body)
            prompt = prompt.replace("{REQUEST}", helpers.bytesToString(request_bytes))
            prompt = prompt.replace("{RESPONSE}", helpers.bytesToString(response))
            prompt = prompt.replace("{IS_TRUNCATED_PROMPT}", str(is_truncated))
            
            return prompt
        except Exception as e:
            if self.stdout:
                self.stdout.println("Error processing prompt: " + str(e))
            else:
                print("Error processing prompt: " + str(e))
            return prompt
