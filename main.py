import jwt
import datetime
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from services.content_generator import generate_content
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

# Initialize Flask app, DB, and other services
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://admin:pgpassword@localhost:5434/mindmate'  # Replace with actual database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'somesecretkey'  # Secret key for encoding/decoding JWT
app.config['S3_BUCKET'] = 'aizenstorage'
app.config['AWS_ACCESS_KEY_ID'] = 'AKIAXYKJUVWLYBWWVLUA'
app.config['AWS_SECRET_ACCESS_KEY'] = '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'

CORS(app)
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

    def __repr__(self):
        return f'<User {self.username}>'

# BlogPosts model
class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default='draft')  # draft, scheduled, published
    publish_date = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
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
        
        # Return the counts as a JSON response
        return jsonify({
            "user_id": user.id,
            "published_posts": published_count,
            "scheduled_posts": scheduled_count
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
    data = request.get_json()
    title = data.get('title')
    content_key_points = data.get('content')
    publish_date_str = data.get('publish_date')

    if not title or not content_key_points:
        return jsonify({"error": "Title and content key points are required"}), 400

    try:
        content = generate_content(content_key_points)
        publish_date = None
        # Step 2: Convert publish_date to datetime if provided
        publish_date = None
        if publish_date_str:
            try:
                publish_date = datetime.fromisoformat(publish_date_str)
            except ValueError:
                return jsonify({"error": "Invalid date format. Use ISO format: YYYY-MM-DDTHH:MM:SS"}), 400

        # Step 3: Publish to WordPress
        post_title = f"Blog on {title}" 
        # Optional: Post the generated content to WordPress (if the user has WordPress credentials)
        if user.wordpress_site_url and user.wordpress_username and user.wordpress_password:
            post_id = publish_to_wordpress(title=post_title, content=content, wp_password=user.wordpress_password, wp_site_url= user.wordpress_site_url, wp_username=user.wordpress_username,  status="future" if publish_date else "publish", publish_date=publish_date)
            if not post_id:
                return jsonify({"error": "Failed to publish the blog to WordPress"}), 500

        blog_post = BlogPost(
            user_id=user.id,
            title=title,
            content=content_key_points,
            status='scheduled' if publish_date else 'published',
            publish_date=publish_date
        )
        
        db.session.add(blog_post)
        db.session.commit()

        delay = (publish_date - datetime.utcnow().replace(tzinfo=timezone.utc)).total_seconds()
        if delay < 0:
            delay = 0
        # Schedule PostgreSQL trigger if publish_date exists
        if publish_date:
             # Use threading to run the task
            thread = threading.Thread(target=schedule_trigger_in_thread, args=(blog_post.id, delay))
            thread.start()

        return jsonify({"message": "Blog post generated successfully"}), 200
    except Exception as e:
        return jsonify({"error": f"Error generating blog: {str(e)}"}), 500

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
    
if __name__ == '__main__':
    app.run(debug=True)
