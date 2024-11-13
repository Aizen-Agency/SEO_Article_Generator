from openai import OpenAI
from config.settings import OPENAI_API_KEY
import json
import datetime
from openai import OpenAI
import requests
import urllib.parse
from deep_translator import GoogleTranslator


# Initialize system as a dictionary to hold various properties
system = {}

client = OpenAI(api_key=OPENAI_API_KEY)

def text_translate(text, src_lang, target_lang):
    try:
        translated = GoogleTranslator(source=src_lang, target=target_lang).translate(text=text)
        return translated
    except Exception as e:
        print(f"An error occurred during translation: {e}")
        return text

def mix_translate(text, src_lang, target_lang):
    try:
        translated = GoogleTranslator(source=src_lang, target=target_lang).translate(text=text)
        translated_back = GoogleTranslator(source=target_lang, target=src_lang).translate(text=translated)
        return translated_back
    except Exception as e:
        print(f"An error occurred during translation: {e}")
        return text

def setup_openai(model):
    system['model'] = model
    system['humanizer'] = """You are HUMIZER and DECOHERE, an AI designed to humanize and decohere AI-generated content so that it passes as human in an academic voice."""
    system['grammar'] = "Only fix grammar problems without changing the words and order of the sentence."

def humanize_openai(text):
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": system['humanizer']},
                {"role": "user", "content": text}
            ],
            temperature=2
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"An error occurred during OpenAI connection: {e}")
        return text

def getScore(input_text):
    url = 'https://writer.com/wp-admin/admin-ajax.php'
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
    }
    input_encoded = urllib.parse.quote(input_text)
    payload = {"action": "ai_content_detector_v2", "inputs": input_encoded, "token": ""}
    response = requests.post(url, data=payload, headers=headers)
    if response.status_code == 200:
        resp = json.loads(response.text)
        return resp['label'] == 'Human-Generated'
    else:
        print("POST request failed with status code:", response.status_code)
        return False

def grammar_check_openai(text):
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": system['grammar']},
                {"role": "user", "content": text}
            ],
            temperature=0.5
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"An error occurred during OpenAI connection: {e}")
        return text

def process_text(input_text, target_lang="arabic", model="gpt-3.5-turbo", grammar=False):
    setup_openai(model)
    output_text = input_text
    src_lang = 'english'

    # Check if content is human-like
    if getScore(output_text):
        return output_text

    while True:
        output_text = mix_translate(output_text, src_lang, target_lang)
        if getScore(output_text):
            break
        output_text = humanize_openai(output_text)
        if getScore(output_text):
            break
        output_text = mix_translate(output_text, src_lang, target_lang)
        if getScore(output_text):
            break

    if grammar:
        output_text = grammar_check_openai(output_text)

    return output_text