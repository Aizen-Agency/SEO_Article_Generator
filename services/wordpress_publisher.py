# services/wordpress_publisher.py

import requests
from requests.auth import HTTPBasicAuth
from config.settings import WORDPRESS_SITE_URL, WORDPRESS_USERNAME, WORDPRESS_PASSWORD

def publish_to_wordpress(title, content, status="draft"):
    url = f"{WORDPRESS_SITE_URL}/wp-json/wp/v2/posts"
    auth = HTTPBasicAuth(WORDPRESS_USERNAME, WORDPRESS_PASSWORD)
    
    data = {
        "title": title,
        "content": content,
        "status": status,
    }
    
    response = requests.post(url, json=data, auth=auth)
    response.raise_for_status()
    
    post_id = response.json().get("id")
    return post_id
