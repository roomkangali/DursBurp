# DursBurp - AI-Powered Security Analysis for Burp Suite

DursBurp is a Burp Suite extension that integrates the power of large language models (LLMs) from OpenAI, Google Gemini, and Groq to assist in security analysis. With DursBurp, you can send HTTP request/response pairs directly to an AI for in-depth vulnerability analysis, all within the Burp Suite interface.

## Key Features

- **On-Demand Analysis**: Analyzes only the requests you choose, giving you full control.
- **Multi-API Support**: Integrates with OpenAI, Google Gemini, and Groq APIs.
- **Structured Reports**: Displays analysis results in a clean, tabbed format similar to the native Burp Scanner, with "Advisory," "Request," and "Response" tabs.
- **Customizable Prompts**: Edit and save your own instruction prompts to tailor the AI's analysis to your specific needs.
- **Finding Management**: Mark findings as false positives with a green visual indicator.
- **Responsive UI**: Analysis runs in the background to ensure the Burp Suite interface never freezes.

## How It Works

DursBurp works as an intelligent security assistant, not an automated scanner.

1.  **Select a Target**: Within Burp Suite (e.g., in Proxy > HTTP history), right-click on a request/response pair you want to analyze.
2.  **Send for Analysis**: Select "Extensions" > "DursBurp" > "Analyze with DursBurp".
3.  **Prompt Generation**: The extension takes the template from the "DursBurp" tab, filling in placeholders like `{URL}` and `{REQUEST_BODY}` with real data from your selected traffic.
4.  **AI Analysis**: The completed prompt is sent to your configured AI service (OpenAI, Gemini, or Groq).
5.  **Report Generation**: The AI analyzes the full context of the request and response and generates a structured vulnerability report.
6.  **View Results**: The report is parsed and displayed cleanly in the results panel within the "DursBurp" tab, ready for your review.

## Installation

1.  **Download Jython**: This extension is written in Python and requires Jython to run within the Java-based Burp Suite.
    -   Visit the official Jython website: [https://www.jython.org/download](https://www.jython.org/download)
    -   Download the **Jython Standalone** (`.jar`) file.
2.  **Configure Burp Suite**:
    -   Open Burp Suite.
    -   Go to the **Extensions** > **Extensions Settings** tab.
    -   Under the **Python Environment** section, click **Select file** and choose the Jython Standalone `.jar` file you just downloaded.
3.  **Install the DursBurp Extension**:
    -   Still in the **Extensions** tab, click **Add**.
    -   Select the `dursburp.py` file as the extension file.
    -   Ensure the extension loads without errors in the "Output" tab.

## Configuration and Usage

1.  **Open the DursBurp Tab**: After a successful installation, a new tab named "DursBurp" will appear in Burp Suite.
2.  **Select API and Enter Key**:
    -   Choose the AI provider you want to use (OpenAI, Gemini, or Groq).
    -   Enter your valid API key in the corresponding field.
    -   Select the model you want to use from the dropdown menu.
3.  **Save Settings**: Click **Save Settings**.
4.  **Start Analyzing**:
    -   Go to the Proxy > HTTP history tab or send a request to Repeater.
    -   Right-click on the request you want to analyze.
    -   Select **Extensions** > **DursBurp** > **Analyze with DursBurp**.
    -   The results will appear in the results panel within the DursBurp tab.

## Prompt Customization

One of the most powerful features of DursBurp is the ability to customize the instructions given to the AI.

Inside the "DursBurp" tab, you will see a large text box labeled "Custom Prompt". The text in this box is the template used for every analysis. You can edit it as you wish. For example, if you want the AI to focus only on SQL Injection, you can change the prompt to reflect that.

When you're done editing, simply click **Save Settings**, and all subsequent analyses will use your new prompt.

## Roadmap & Future Features

DursBurp is under continuous development. Here are some features planned for future updates:

-   **Smart Active Scanning**: Implement a workflow where the AI not only analyzes but also generates an attack plan (*payloads*). The user can then approve and launch the active scan, with the AI analyzing the results to confirm vulnerabilities.
-   **Full Target & Issues Integration**: Automatically add confirmed findings to Burp Suite's "Target" and "Issues" tabs for seamless reporting.
-   **Session & Context Management**: The ability to "remember" a testing session, allowing the AI to perform deeper contextual analysis (e.g., detecting IDORs by comparing requests from different users).
-   **Support for Other Burp Tools**: Integrate DursBurp with other tools like Intruder and Repeater for more dynamic testing workflows.
-   **Enhanced Visualization**: Add graphs or visual summaries of findings within the DursBurp tab.
