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
            {"role": "system", "content": "You are an SEO expert that optimizes content while maintaining readability. Just return the optimized content, no need to explain.  Do not use any special characters like asterisks or hashtags in the content"},
            {"role": "user", "content": prompt},
        ]
    )
    
    # Remove any special characters from the optimized content
    optimized_content = response.choices[0].message.content
    optimized_content = ''.join(char for char in optimized_content if char not in '*#')
    
    return optimized_content


def generate_content(topic, keywords=[], tone="informative", style="blog", length="medium", prompt=None):
    if prompt is None:
        prompt = f"Write a {tone} blog post about {topic} in a {style} style with {length} length. Also generate a catchy title for this blog post."
    else:
        prompt = f"{prompt}. Topic of blog post: {topic}"

    # Modify the prompt to include the language instruction
    print("prompt", prompt)
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a helpful assistant that writes high-quality blog posts in the specified language. Always start your response with a title on the first line followed by two newlines before the content. Do not use any special characters like asterisks or hashtags in the title or content."},
            {"role": "user", "content": prompt},
        ]
    )
    response_text = response.choices[0].message.content
    
    # Split response into title and content
    lines = response_text.split('\n')
    title = lines[0].strip()
    content = '\n'.join(lines[2:]).strip()
    
    # Remove any remaining special characters
    title = ''.join(char for char in title if char not in '*#')
    content = ''.join(char for char in content if char not in '*#')
    
    if keywords:
        content = optimize_for_seo(content, keywords)
        
    return {
        'title': title,
        'content': content
    }
