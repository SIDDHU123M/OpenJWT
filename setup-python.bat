@echo off
echo 🚀 Setting up OpenJWT Python Development Environment

cd python-version

echo 🐍 Creating virtual environment...
python -m venv venv

echo 🔧 Activating virtual environment...
call venv\Scripts\activate.bat

echo 📦 Installing dependencies...
pip install -r requirements.txt

echo 📝 Creating environment file...
if not exist .env (
    copy .env.example .env
    echo ✅ Created .env file from example
) else (
    echo ⚠️  .env file already exists
)

echo 🧪 Running tests...
python -m pytest test_app.py -v

echo ✅ Setup complete!
echo.
echo To start the development server:
echo   cd python-version
echo   venv\Scripts\activate.bat
echo   python app.py
echo.
echo To start with gunicorn:
echo   cd python-version
echo   venv\Scripts\activate.bat
echo   gunicorn app:app

pause
