# DursBurp - AI-Powered Security Analysis for Burp Suite
#
# Author: Kang Ali
# Version: 1.0.0
# GitHub: https://github.com/roomkangali/DursBurp
#
# This module handles all communication with the external AI APIs.

import json
import urllib2

class APIClient:
    def call_api(self, api_choice, api_key, model, prompt, max_tokens):
        if api_choice == "OpenAI":
            return self.call_openai_api(api_key, model, prompt, max_tokens)
        elif api_choice == "Gemini":
            return self.call_gemini_api(api_key, model, prompt, max_tokens)
        else: # Groq
            return self.call_groq_api(api_key, model, prompt, max_tokens)
    
    def call_openai_api(self, api_key, model, prompt, max_tokens):
        try:
            url = "https://api.openai.com/v1/chat/completions"
            headers = {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + api_key
            }
            data = json.dumps({
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_tokens
            }).encode('utf-8')
            
            request = urllib2.Request(url, data, headers)
            response = urllib2.urlopen(request)
            result = json.loads(response.read().decode('utf-8'))
            return result["choices"][0]["message"]["content"]
        except Exception as e:
            print("OpenAI API error: " + str(e))
            return None
    
    def call_gemini_api(self, api_key, model, prompt, max_tokens):
        try:
            url = "https://generativelanguage.googleapis.com/v1beta/models/{0}:generateContent?key={1}".format(model, api_key)
            headers = {"Content-Type": "application/json"}
            data = json.dumps({
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"maxOutputTokens": max_tokens}
            }).encode('utf-8')
            
            request = urllib2.Request(url, data, headers)
            response = urllib2.urlopen(request)
            result = json.loads(response.read().decode('utf-8'))
            return result["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as e:
            print("Gemini API error: " + str(e))
            return None

    def call_groq_api(self, api_key, model, prompt, max_tokens):
        try:
            url = "https://api.groq.com/openai/v1/chat/completions"
            headers = {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + api_key,
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            }
            data = json.dumps({
                "model": model,
                "messages": [{"role": "user", "content": prompt}]
            }).encode('utf-8')
            
            request = urllib2.Request(url, data, headers)
            response = urllib2.urlopen(request)
            result = json.loads(response.read().decode('utf-8'))
            return result["choices"][0]["message"]["content"]
        except Exception as e:
            print("Groq API error: " + str(e))
            return None
