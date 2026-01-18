from app import create_app
import os

app = create_app()

if __name__ == '__main__':
    # Ensure upload folder exists
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    app.run(debug=True, port=5000)