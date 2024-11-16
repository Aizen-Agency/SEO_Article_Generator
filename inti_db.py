from main import app, db, User  # Import your Flask app and the SQLAlchemy instance
from sqlalchemy.sql import text
from sqlalchemy.exc import SQLAlchemyError


# Create the tables based on the models defined in your app
with app.app_context():
    db.create_all()
    print("Database initialized and tables created.")
    
    def create_trigger_function():
        try:
            # Use text() to wrap the SQL query
            db.session.execute(text("""
                CREATE OR REPLACE FUNCTION update_blog_post_status()
                RETURNS trigger AS $$
                BEGIN
                    -- Update the status to 'unapproved' once the trigger is fired
                    UPDATE public.blog_post
                    SET status = 'unapproved'
                    WHERE id = NEW.id;
                    RETURN NEW;
                END;
                $$ LANGUAGE plpgsql;
            """))
            db.session.commit()
            print("Trigger function created successfully.")
        except Exception as e:
            db.session.rollback()
            print(f"Error creating trigger function: {e}")

    def create_trigger():
        try:
            # Check if the trigger already exists
            trigger_check_query = """
                SELECT 1
                FROM pg_trigger
                WHERE tgname = 'schedule_publish_trigger';
            """
            result = db.session.execute(text(trigger_check_query)).scalar()

            if result:
                print("Trigger 'schedule_publish_trigger' already exists.")
            else:
                # Create the trigger if it doesn't exist
                create_trigger_query = """
                    CREATE TRIGGER schedule_publish_trigger
                    AFTER INSERT ON public.blog_post
                    FOR EACH ROW
                    EXECUTE FUNCTION update_blog_post_status();
                """
                db.session.execute(text(create_trigger_query))
                db.session.commit()
                print("Trigger created successfully.")
        except SQLAlchemyError as e:
            db.session.rollback()
            print(f"Error creating trigger: {str(e)}")

    # Call these functions to ensure the trigger and function are created
    create_trigger_function()
    create_trigger()