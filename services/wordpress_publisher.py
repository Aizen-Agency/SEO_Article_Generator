# services/wordpress_publisher.py


from wordpress_xmlrpc import Client, WordPressPost
from wordpress_xmlrpc.methods import posts
from config.settings import WORDPRESS_SITE_URL, WORDPRESS_USERNAME, WORDPRESS_PASSWORD

# Create a WordPress client
wp = Client(WORDPRESS_SITE_URL, WORDPRESS_USERNAME, WORDPRESS_PASSWORD)


def publish_to_wordpress(title, content, status="draft"):
    
    # Create a new post
    post = WordPressPost()
    post.title = title
    post.content = content
    post.post_status = status

    # Publish the post
    wp.call(posts.NewPost(post))




