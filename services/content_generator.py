# services/content_generator.py

from openai import OpenAI
from config.settings import OPENAI_API_KEY


client = OpenAI(api_key=OPENAI_API_KEY)

def optimize_for_seo(content, keywords):
    """
    Optimize the content for SEO using provided keywords
    """
    keywords_str = ", ".join(keywords)
    prompt = f"Optimize this content for SEO using these keywords: {keywords_str}. Content: {content}"
    
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are an SEO expert that optimizes content while maintaining readability."},
            {"role": "user", "content": prompt},
        ]
    )
    
    return response.choices[0].message.content

def generate_content(topic, keywords=[], tone="informative", style="blog", length="medium"):
    prompt = f"Write a {tone} blog post about {topic} in a {style} style with {length} length."
    
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a helpful assistant that writes high-quality blog posts."},
            {"role": "user", "content": prompt},
        ]
    )
    
    content = response.choices[0].message.content
    
    if keywords:
        content = optimize_for_seo(content, keywords)
        
    return content
