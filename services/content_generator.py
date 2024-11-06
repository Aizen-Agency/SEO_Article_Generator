# services/content_generator.py

from openai import OpenAI
from config.settings import OPENAI_API_KEY


client = OpenAI(api_key=OPENAI_API_KEY)

def generate_content(topic, tone="informative", style="blog", length="medium"):
    prompt = f"Write a {tone} blog post about {topic} in a {style} style with {length} length."
    
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a helpful assistant that writes high-quality blog posts."},
            {"role": "user", "content": prompt},
        ]
    )
    print(response)
    content = response.choices[0].message.content

    return content
