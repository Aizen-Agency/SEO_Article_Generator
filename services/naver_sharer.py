# services/naver_sharer.py

import requests
from config.settings import NAVER_CLIENT_ID, NAVER_CLIENT_SECRET, NAVER_BLOG_ID

def share_to_naver(post_id, post_title, post_url):
    url = "https://openapi.naver.com/blog/writePost.json"
    headers = {
        "X-Naver-Client-Id": NAVER_CLIENT_ID,
        "X-Naver-Client-Secret": NAVER_CLIENT_SECRET
    }
    data = {
        "blogId": NAVER_BLOG_ID,
        "title": post_title,
        "description": f"Check out the latest post: {post_url}",
    }
    
    response = requests.post(url, headers=headers, data=data)
    response.raise_for_status()
    return response.json()
