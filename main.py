# main.py

from services.content_generator import generate_content
from services.wordpress_publisher import publish_to_wordpress
from services.naver_sharer import share_to_naver

def main():
    # Step 1: Generate Content
    topic = "The Future of AI in Content Creation"
    content = generate_content(topic)

    # Step 2: Publish to WordPress
    post_title = f"Blog on {topic}"
    post_id = publish_to_wordpress(title=post_title, content=content, status="publish")

    # Step 3: Share on Naver
    wordpress_post_url = f"https://yourwordpresssite.com/?p={post_id}"
    naver_response = share_to_naver(post_id, post_title, wordpress_post_url)
    
    print("Post shared successfully on Naver:", naver_response)

if __name__ == "__main__":
    main()
