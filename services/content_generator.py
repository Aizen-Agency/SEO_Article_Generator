# services/content_generator.py

import openai
from config.settings import OPENAI_API_KEY

openai.api_key = OPENAI_API_KEY

def generate_content(topic, tone="informative", style="blog", length="medium"):
    prompt = f"Write a {tone} blog post about {topic} in a {style} style with {length} length."
    
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are a helpful assistant that writes high-quality blog posts."},
            {"role": "user", "content": prompt},
        ]
    )
    content = response['choices'][0]['message']['content']
    return content
