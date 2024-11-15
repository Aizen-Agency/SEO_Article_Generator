from wordpress_xmlrpc import Client, WordPressPost
from wordpress_xmlrpc.methods import posts
from wordpress_xmlrpc.methods.posts import GetPost
from datetime import datetime


def publish_to_wordpress(title, content, wp_site_url, wp_username, wp_password, status="draft", publish_date=None):
    """
    Publishes or schedules a post on WordPress and returns the post's URL.

    Args:
        title (str): Title of the post.
        content (str): Content of the post.
        status (str, optional): Status of the post ('draft' or 'publish').
        publish_date (datetime, optional): Date and time for scheduling the post. 
                                           If None, the post is published immediately.
    
    Returns:
        str: The URL of the published or scheduled post.
    """
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

    print(wp_site_url)
    print(wp_password)
    print(wp_username)
    print(post)
    # Publish or schedule the post
    post_id = wp.call(posts.NewPost(post))

    # Retrieve the post URL using the post ID
    post_details = wp.call(GetPost(post_id))
    post_url = f"{wp_site_url}/{post_details.slug}"

    return post_url
