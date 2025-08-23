import os
from dotenv import load_dotenv
import google.generativeai as genai
# import gradio as gr
#from pyngrok import ngrok
from PIL import Image
from flask import Flask, render_template

# ngrok.kill()
# public_url = ngrok.connect(7860)
# print("Ngrok Public URL:", public_url)

load_dotenv(override=True)
google_api_key = os.getenv('GEMINI_API_KEY')

if google_api_key:
    print(f"Google API Key exists and begins {google_api_key[:8]}")
else:
    print("Google API Key not set")

genai.configure(api_key=google_api_key)
model = genai.GenerativeModel('gemini-2.5-flash')

system_message = """You are an expert career consultant. Analyze the user's resume against their target job title and provide actionable feedback.
Task:

Resume Analysis: Evaluate content, format, and alignment with target job requirements
Improvement Suggestions: Provide specific changes for better job matching
Skills Gap Assessment: Identify missing skills/knowledge and recommend learning resources

Response Format:

Strengths: Top 2-3 strong points
Key Improvements: Specific changes needed
Skills to Develop: Priority learning recommendations with resources
Quick Wins: Immediate actionable fixes

Keep feedback constructive, specific, and actionable. Focus on maximizing interview chances for the target role.
Always end your response by asking:

If this is your first analysis: "Would you like me to generate an improved version of your resume incorporating all the suggested changes?"
Always ask: "Would you like a practice interview session for this role to help you prepare for common questions and scenarios?"

Generate link for the corresponding course in Udemy and Coursera website for the suggested SKills which is to be developed. 
Show search results for that website,
Example:
    https://www.udemy.com/courses/search/?q=agentic+ai&src=sac (which is the search result for agentic ai)
    https://www.coursera.org/search?query=machine%20learning (which is the search result for machine learning)

Note: Only ask about resume generation if you haven't already created an improved resume in this conversation."""

chat_session = model.start_chat(history=[{"role": "user", "parts": [system_message]}])

def chat_fn(message, history, image=None):
    print(f"\nUser: {message}")
    print(f"History: {history}")
    input = [message]
    if image is not None:
        input.append(image)
    response = chat_session.send_message(input, stream=True)
    
    result = ""
    yielded = False
    for chunk in response:
        if chunk.text:
            result += chunk.text
            yield result
            yielded = True
    
    if not yielded:
        yield "Sorry, I couldn't generate a response."
    
    print(f"Assistant: {result}")

# gr.ChatInterface(
#     fn=chat_fn,
#     chatbot=gr.Chatbot(type="messages", height=500),
#     title="Resume Enhancer",
#     description="Chat with AI. You can also upload an image.",
#     additional_inputs=[
#         gr.Image(type="pil", label="Upload an Image (optional)")
#     ],
# ).launch(share=False, server_port=7860)

app = Flask(__name__)
@app.route("/")
def home():
    return render_template("home.html")

@app.route("/register")
def register():
    return render_template('reg-log.html', form_type="register")

@app.route("/login")
def login():
    return render_template('reg-log.html', form_type="login")

@app.route("/chatbot")
def chat():
    return render_template("chatbot.html")

@app.route("/To-Do")
def to_do():
    return render_template("to-do.html")

if __name__ == '__main__':
    app.run(host='0.0.0.0',debug=True)