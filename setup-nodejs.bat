@echo off
echo 🚀 Setting up OpenJWT Node.js Development Environment

cd nodejs-version

echo 📦 Installing dependencies...
npm install

echo 📝 Creating environment file...
if not exist .env (
    copy .env.example .env
    echo ✅ Created .env file from example
) else (
    echo ⚠️  .env file already exists
)

echo 🧪 Running tests...
npm test

echo ✅ Setup complete!
echo.
echo To start the development server:
echo   cd nodejs-version
echo   npm run dev
echo.
echo To start the production server:
echo   cd nodejs-version  
echo   npm start

pause
