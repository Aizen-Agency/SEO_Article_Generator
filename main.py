import jwt
import datetime
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from services.content_generator import generate_content, optimize_for_seo
from services.wordpress_publisher import publish_to_wordpress
from services.naver_sharer import share_to_naver
from datetime import datetime
import boto3
from functools import wraps
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, timezone
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import text
import asyncio
import threading
import os
from dotenv import load_dotenv

# Load environment variables from a .env file
load_dotenv()

# Initialize Flask app, DB, and other services
app = Flask(__name__)

database_url = os.getenv('DATABASE_URL')

# Replace "postgres://" with "postgresql+psycopg2://" for SQLAlchemy compatibility
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql+psycopg2://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url  # Default fallback if the env variable is not set
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')  # Secret key for encoding/decoding JWT
app.config['S3_BUCKET'] = os.getenv('S3_BUCKET')
app.config['AWS_ACCESS_KEY_ID'] = os.getenv('AWS_ACCESS_KEY_ID')
app.config['AWS_SECRET_ACCESS_KEY'] = os.getenv('AWS_SECRET_ACCESS_KEY')

# Enable CORS globally with custom options
CORS(app, 
    origins="*",                   # Allow all origins
    methods=["GET", "POST", "PUT"],       # Allow only GET and POST requests
    supports_credentials=True      # Allow credentials (e.g., cookies)
)



db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# S3 Client
s3 = boto3.client('s3', aws_access_key_id=app.config['AWS_ACCESS_KEY_ID'], aws_secret_access_key=app.config['AWS_SECRET_ACCESS_KEY'])
# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    profile_pic_url = db.Column(db.String(255), nullable=True)
    wordpress_site_url = db.Column(db.String(255), nullable=True)
    wordpress_username = db.Column(db.String(255), nullable=True)
    wordpress_password = db.Column(db.String(255), nullable=True)
    keywords = db.Column(db.String(255), nullable=True)

    def __repr__(self):
        return f'<User {self.username}>'

# BlogPosts model
class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    updated_content = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), default='draft')  # draft, scheduled, published, unapproved
    publish_date = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    image_url = db.Column(db.String(255), nullable=True)
# Utility function to encode JWT token
def encode_auth_token(user_id):
    try:
        payload = {
            'exp': datetime.utcnow() + timedelta(hours=1),
            'iat': datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    except Exception as e:
        return str(e)

# Decorator to check JWT token
def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            parts = request.headers['Authorization'].split(" ")
            if len(parts) == 2 and parts[0] == 'Bearer':
                token = parts[1]
            else:
                return jsonify({'error': 'Invalid token format. Expected "Bearer <token>"'}), 400
        if not token:
            return jsonify({'error': 'Token is missing!'}), 401
        try:
            print(token)
            print(app.config['SECRET_KEY'])
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            print(payload)
            user_id = payload.get('sub')
            if not user_id:
                return jsonify({'error': 'Invalid token. User ID missing in token payload'}), 401
            user = User.query.get(user_id)
            if not user:
                return jsonify({'error': 'User not found'}), 404
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token!'}), 401
        return f(user, *args, **kwargs)
    return decorator

@app.route('/user/post-stats', methods=['GET'])
@token_required
def get_post_stats(user):
    try:
        # Fetch the counts for published and scheduled posts
        published_count = BlogPost.query.filter_by(user_id=user.id, status='published').count()
        scheduled_count = BlogPost.query.filter_by(user_id=user.id, status='scheduled').count()
        unapproved_count = BlogPost.query.filter_by(user_id=user.id, status='unapproved').count()

        # Get all blog posts for this user
        blog_posts = BlogPost.query.filter_by(user_id=user.id).all()
        
        # Count total keywords across all posts
        total_keywords = 0
        if user.keywords:
            # Split keywords string by comma and count non-empty keywords
            keywords_list = [k.strip() for k in user.keywords.split(',') if k.strip()]
            total_keywords += len(keywords_list)

        # Return the counts as a JSON response
        return jsonify({
            "user_id": user.id,
            "published_posts": published_count,
            "scheduled_posts": scheduled_count,
            "unapproved_posts": unapproved_count,
            "totalSEOKeywords": total_keywords
        }), 200

    except Exception as e:
        # Handle any errors
        return jsonify({"error": str(e)}), 500

# Schedule PostgreSQL trigger in a separate thread with proper app context
def schedule_trigger_in_thread(blog_post_id, delay_seconds):
    # Use the app context explicitly
    with app.app_context():
        asyncio.run(schedule_trigger(blog_post_id, delay_seconds))

# Route to generate a blog post (protected route)
@app.route('/generate-blog', methods=['POST'])
@token_required
def generate_blog(user):
    print(request.form)
    data = request.form
    content_key_points = data.get('content')
    prompt = data.get('prompt')
    publish_date_str = data.get('publish_date')
    keywords = user.keywords
    keywords = keywords.split(',') if keywords else []

    # Define allowed file extensions for images
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

    def allowed_file(filename):
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

    try:
        # Log the received image file
        if 'image' in request.files:
            image = request.files['image']
        else:
            print("No image file received")

        response = generate_content(content_key_points, prompt=prompt) if prompt else generate_content(content_key_points)
        title = response['title']
        content = response['content']
        updated_content = optimize_for_seo(content, keywords)
        publish_date = None
        if publish_date_str:
            try:
                publish_date = datetime.fromisoformat(publish_date_str)
            except ValueError:
                return jsonify({"error": "Invalid date format. Use ISO format: YYYY-MM-DDTHH:MM:SS"}), 400

        # Handle image upload
        image_url = None
        if 'image' in request.files:
            image = request.files['image']
            if image and allowed_file(image.filename):
                filename = secure_filename(image.filename)
                try:
                    s3.upload_fileobj(
                        image,
                        app.config['S3_BUCKET'],
                        filename,
                        ExtraArgs={'ContentType': image.content_type}
                    )
                    image_url = f"https://{app.config['S3_BUCKET']}.s3.amazonaws.com/{filename}"
                except Exception as e:
                    return jsonify({"error": f"Error uploading image to S3: {str(e)}"}), 500

        blog_post = BlogPost(
            user_id=user.id,
            title=title,
            content=content,
            updated_content=updated_content,
            status='unapproved',
            publish_date=publish_date,
            image_url=image_url
        )
        
        db.session.add(blog_post)
        db.session.commit()

        return jsonify({
            "message": "Blog post generated successfully and marked as unapproved",
            "post_id": blog_post.id,
            "image_url": image_url
        }), 200
    except Exception as e:
        return jsonify({"error": f"Error generating blog: {str(e)}"}), 500
    
    
@app.route('/update-blog-keywords', methods=['POST'])
@token_required
def update_blog_keywords(user):
    data = request.get_json()
    new_keywords = data.get('keywords')
    new_keywords = new_keywords.split(',') if new_keywords else []
    try:
        user.keywords = ','.join(new_keywords)
        db.session.commit()
        return jsonify({"message": "User keywords updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": f"Error updating user keywords: {str(e)}"}), 500

@app.route('/get-blog-keywords', methods=['GET']) 
@token_required
def get_blog_keywords(user):
    try:
        keywords = user.keywords.split(',') if user.keywords else []
        return jsonify({
            "keywords": keywords
        }), 200
    except Exception as e:
        return jsonify({"error": f"Error fetching user keywords: {str(e)}"}), 500
    
@app.route('/approve-and-publish', methods=['POST'])
@token_required
def approve_and_publish(user):
    data = request.get_json()
    post_id = data.get('post_id')

    if not post_id:
        return jsonify({"error": "Post ID is required"}), 400

    try:
        blog_post = BlogPost.query.filter_by(id=post_id, user_id=user.id, status='unapproved').first()
        if not blog_post:
            return jsonify({"error": "Unapproved blog post not found or you don't have permission to approve it"}), 404

        if user.wordpress_site_url and user.wordpress_username and user.wordpress_password:
            post_url = publish_to_wordpress(
                title=blog_post.title,
                content=blog_post.content,
                wp_password=user.wordpress_password,
                wp_site_url=user.wordpress_site_url,
                wp_username=user.wordpress_username,
                status="publish",
                publish_date=blog_post.publish_date,
                image_url=blog_post.image_url  # Send image_url to WordPress
            )
            if not post_url:
                return jsonify({"error": "Failed to publish the blog to WordPress"}), 500
            
            if blog_post.publish_date:
                blog_post.status = 'scheduled'
            else:
                blog_post.status = 'published'
            db.session.commit()
            
            if blog_post.publish_date:
                current_time = datetime.utcnow().replace(tzinfo=timezone.utc)
                if blog_post.publish_date.replace(tzinfo=timezone.utc) > current_time:
                    delay = (blog_post.publish_date.replace(tzinfo=timezone.utc) - current_time).total_seconds()
                else:
                    delay = 0
                # Schedule PostgreSQL trigger if publish_date exists
                # Use threading to run the task
                thread = threading.Thread(target=schedule_trigger_in_thread, args=(blog_post.id, delay))
                thread.start()

            return jsonify({"message": "Blog post approved and published successfully", "wordpress_url": post_url}), 200
        else:
            return jsonify({"error": "WordPress credentials are missing"}), 400

    except Exception as e:
        return jsonify({"error": f"Error approving and publishing blog post: {str(e)}"}), 500

# Asynchronous trigger function
async def schedule_trigger(blog_post_id, delay_seconds):
    try:
        if delay_seconds > 0:
            await asyncio.sleep(delay_seconds)

        db.session.execute(text(f"""
            UPDATE public.blog_post
            SET status = 'published'
            WHERE id = :blog_post_id
        """), {"blog_post_id": blog_post_id})
        db.session.commit()

    except SQLAlchemyError as e:
        db.session.rollback()
        print(f"Error scheduling trigger: {str(e)}")
        
        
@app.route('/signup', methods=['POST'])
def signup():
    # Get form data
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    profile_pic = request.files.get('profile_pic')  # Get the file from form data

    print(request.form)
    print(profile_pic)
    # Validate input
    if not username or not email or not password or not profile_pic:
        return jsonify({"error": "All fields are required"}), 400

    # Check if user already exists
    existing_user = User.query.filter((User.email == email) | (User.username == username)).first()
    if existing_user:
        return jsonify({"error": "User already exists"}), 400

    # Upload profile picture to S3
    try:
        # Secure the file name and upload to S3
        file_name = secure_filename(f'{username}_{datetime.now().timestamp()}.jpg')
        profile_pic.save(file_name)  # Save temporarily or use direct stream to upload
        s3.upload_file(file_name, app.config['S3_BUCKET'], file_name)
        profile_pic_url = f'https://{app.config["S3_BUCKET"]}.s3.amazonaws.com/{file_name}'
    except Exception as e:
        return jsonify({"error": f"Failed to upload profile picture: {str(e)}"}), 500

    # Hash password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Create new user
    new_user = User(username=username, email=email, password=hashed_password, profile_pic_url=profile_pic_url)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201


# Login route (returns JWT)
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email_or_username = data.get('email_or_username')
    password = data.get('password')

    # Validate input
    if not email_or_username or not password:
        return jsonify({"error": "Email/Username and password are required"}), 400

    # Find user by email or username
    user = User.query.filter((User.email == email_or_username) | (User.username == email_or_username)).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error": "Invalid credentials"}), 401

    # Generate JWT token
    token = encode_auth_token(user.id)

    # Return success response with JWT token
    return jsonify({
        "message": "Login successful",
        "username": user.username,
        "email": user.email,
        "profile_pic": user.profile_pic_url,
        "token": token
    }), 200

# CRUD for WordPress credentials (protected route)
@app.route('/user/wordpress', methods=['GET', 'POST', 'PUT', 'DELETE'])
@token_required
def manage_wordpress_credentials(user):
    if request.method == 'GET':
        # Get WordPress credentials for the logged-in user
        if not user.wordpress_site_url or not user.wordpress_username:
            return jsonify({"error": "WordPress credentials not found"}), 404
        return jsonify({
            "wordpress_site_url": user.wordpress_site_url,
            "wordpress_username": user.wordpress_username
        })

    elif request.method == 'POST':
        # Create/Set WordPress credentials for the logged-in user
        data = request.get_json()
        wordpress_site_url = data.get('wordpress_site_url')
        wordpress_username = data.get('wordpress_username')
        wordpress_password = data.get('wordpress_password')

        # Validate input
        if not wordpress_site_url or not wordpress_username or not wordpress_password:
            return jsonify({"error": "All fields are required"}), 400

        # # Hash the wordpress password for security
        # hashed_wp_password = bcrypt.generate_password_hash(wordpress_password).decode('utf-8')

        # Store credentials in the database
        user.wordpress_site_url = wordpress_site_url
        user.wordpress_username = wordpress_username
        user.wordpress_password = wordpress_password

        db.session.commit()

        return jsonify({"message": "WordPress credentials added successfully"}), 201

    elif request.method == 'PUT':
        # Update WordPress credentials for the logged-in user
        data = request.get_json()
        wordpress_site_url = data.get('wordpress_site_url')
        wordpress_username = data.get('wordpress_username')
        wordpress_password = data.get('wordpress_password')

        # Validate input
        if not wordpress_site_url or not wordpress_username or not wordpress_password:
            return jsonify({"error": "All fields are required"}), 400

        # Hash the new wordpress password for security
        hashed_wp_password = bcrypt.generate_password_hash(wordpress_password).decode('utf-8')

        # Update credentials
        user.wordpress_site_url = wordpress_site_url
        user.wordpress_username = wordpress_username
        user.wordpress_password = hashed_wp_password

        db.session.commit()

        return jsonify({"message": "WordPress credentials updated successfully"}), 200

    elif request.method == 'DELETE':
        # Delete WordPress credentials for the logged-in user
        user.wordpress_site_url = None
        user.wordpress_username = None
        user.wordpress_password = None

        db.session.commit()

        return jsonify({"message": "WordPress credentials removed successfully"}), 200

@app.route('/user/blogs', methods=['GET'])
@token_required
def get_user_blogs(user):
    try:
        # Get the status parameter from the query string
        status = request.args.get('status', 'unapproved')
        
        # Validate the status parameter
        valid_statuses = ['unapproved', 'approved', 'scheduled', 'published']
        if status not in valid_statuses:
            return jsonify({"error": "Invalid status parameter"}), 400
        # Fetch blogs for the logged-in user with the specified status
        blogs = BlogPost.query.filter_by(user_id=user.id, status=status).all()
        # Prepare the response
        blog_list = []
        for blog in blogs:
            blog_list.append({
                "id": blog.id,
                "title": blog.title,
                "content": blog.content,
                "updated_content": blog.updated_content,
                "status": blog.status,
                "publish_date": blog.publish_date.isoformat() if blog.publish_date else None,
                "created_at": blog.created_at.isoformat(),
                "image_url": blog.image_url
            })
        
        return jsonify({
            "user_id": user.id,
            "status": status,
            "blogs": blog_list
        }), 200

    except Exception as e:
        return jsonify({"error": f"Error fetching user blogs: {str(e)}"}), 500

@app.route('/update-blog-content', methods=['PUT'])
@token_required
def update_blog_content(user):
    try:
        data = request.get_json()
        blog_id = data.get('post_id')
        updated_content = data.get('content')

        if not blog_id or not updated_content:
            return jsonify({"error": "Blog ID and updated content are required"}), 400

        blog_post = BlogPost.query.filter_by(id=blog_id, user_id=user.id).first()
        if not blog_post:
            return jsonify({"error": "Blog post not found or you don't have permission to update it"}), 404

        blog_post.updated_content = updated_content
        db.session.commit()

        return jsonify({"message": "Blog content updated successfully"}), 200

    except Exception as e:
        return jsonify({"error": f"Error updating blog content: {str(e)}"}), 500

@app.route('/update-publish-date', methods=['POST'])
@token_required
def update_publish_date(user):
    try:
        data = request.get_json()
        post_id = data.get('post_id')
        publish_date = data.get('publish_date')

        if not post_id:
            return jsonify({"error": "Post ID is required"}), 400

        blog_post = BlogPost.query.filter_by(id=post_id, user_id=user.id).first()
        if not blog_post:
            return jsonify({"error": "Blog post not found or you don't have permission to update it"}), 404

        if publish_date:
            try:
                blog_post.publish_date = datetime.fromisoformat(publish_date)
            except ValueError:
                return jsonify({"error": "Invalid date format. Use ISO format: YYYY-MM-DDTHH:MM:SS"}), 400
        else:
            blog_post.publish_date = None

        db.session.commit()

        return jsonify({"message": "Publish date updated successfully"}), 200

    except Exception as e:
        return jsonify({"error": f"Error updating publish date: {str(e)}"}), 500

@app.route('/update-post-image', methods=['POST'])
@token_required
def update_post_image(user):
    try:
        post_id = request.form.get('post_id')
        image = request.files.get('image')

        if not post_id or not image:
            return jsonify({"error": "Post ID and image are required"}), 400

        blog_post = BlogPost.query.filter_by(id=post_id, user_id=user.id).first()
        if not blog_post:
            return jsonify({"error": "Blog post not found or you don't have permission to update it"}), 404

        # Define allowed file extensions for images
        ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

        def allowed_file(filename):
            return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

        if image and allowed_file(image.filename):
            filename = secure_filename(f'{user.username}_{post_id}_{datetime.now().timestamp()}.jpg')
            try:
                s3.upload_fileobj(
                    image,
                    app.config['S3_BUCKET'],
                    filename,
                    ExtraArgs={'ContentType': image.content_type}
                )
                image_url = f"https://{app.config['S3_BUCKET']}.s3.amazonaws.com/{filename}"
                blog_post.image_url = image_url
                db.session.commit()
                return jsonify({"message": "Image updated successfully", "image_url": image_url}), 200
            except Exception as e:
                return jsonify({"error": f"Error uploading image to S3: {str(e)}"}), 500
        else:
            return jsonify({"error": "Invalid file type"}), 400

    except Exception as e:
        return jsonify({"error": f"Error updating post image: {str(e)}"}), 500
    
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
