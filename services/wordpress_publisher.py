from wordpress_xmlrpc import Client, WordPressPost
from wordpress_xmlrpc.methods import posts, media
from wordpress_xmlrpc.methods.posts import GetPost
from datetime import datetime
import requests  


def publish_to_wordpress(title, content, wp_site_url, wp_username, wp_password, status="draft", publish_date=None, image_url=None):
    """
    Publishes or schedules a post on WordPress and returns the post's URL.

    Args:
        title (str): Title of the post.
        content (str): Content of the post.
        wp_site_url (str): WordPress site URL.
        wp_username (str): WordPress username.
        wp_password (str): WordPress password.
        status (str, optional): Status of the post ('draft' or 'publish').
        publish_date (datetime, optional): Date and time for scheduling the post. 
                                           If None, the post is published immediately.
        image_url (str, optional): URL of the image to be included in the post.
    
    Returns:
        str: The URL of the published or scheduled post.
    """
    print(f"Publishing to WordPress: {wp_site_url}, {wp_username}, {wp_password}")
    # Create a WordPress client
    wp = Client(wp_site_url, wp_username, wp_password)
    
    # Create a new post
    post = WordPressPost()
    post.title = title
    post.content = content
    post.post_status = status

    # Set the date if scheduling is requested
    if publish_date:
        post.date = publish_date

    # Add image to the post if image_url is provided
    if image_url:
        # Prepare image data
        image_data = {
            'name': 'image.jpg',
            'type': 'image/jpeg',  # Adjust if needed based on the image type
            'bits': requests.get(image_url).content
        }
        
        # Upload the image
        response = wp.call(media.UploadFile(image_data))
        attachment_id = response['id']
        
        # Set the uploaded image as the featured image of the post
        post.thumbnail = attachment_id
        
        # You can also add the image to the content if desired
        image_html = f'<img src="{response["url"]}" alt="Featured Image">'
        post.content = image_html + post.content

    # Publish or schedule the post
    post_id = wp.call(posts.NewPost(post))

    # Retrieve the post URL using the post ID
    post_details = wp.call(GetPost(post_id))
    post_url = f"{wp_site_url}/{post_details.slug}"

    return post_url
