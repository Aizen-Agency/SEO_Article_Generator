from flask import Flask, request, jsonify
from flask_cors import CORS
from services.content_generator import generate_content
from services.wordpress_publisher import publish_to_wordpress
from services.naver_sharer import share_to_naver

app = Flask(__name__)
CORS(app)  # Enables CORS for all routes

@app.route('/generate-blog', methods=['POST'])
def generate_blog():
    data = request.get_json()
    title = data.get('title')
    keywords = data.get('keywords')
    content_key_points = data.get('content')

    # Step 1: Generate Content
    content = generate_content(content_key_points)

    # Step 2: Publish to WordPress
    post_title = f"Blog on {title}"
    post_id = publish_to_wordpress(title=post_title, content=content, status="publish")

    # Step 3: Share on Naver
    wordpress_post_url = f"https://yourwordpresssite.com/?p={post_id}"
    #naver_response = share_to_naver(post_id, post_title, wordpress_post_url)
    
    # Return a success response with post ID and Naver response
    return jsonify({
        "message": "Blog post generated and shared successfully.",
        "post_id": post_id,
        "naver_response": ""
    }), 200

if __name__ == "__main__":
    app.run(debug=True)
