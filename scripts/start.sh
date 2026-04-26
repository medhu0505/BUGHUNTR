#!/bin/bash

echo "Building frontend..."
npm install
npm run build

echo "Installing backend dependencies..."
cd backend
pip install -r requirements.txt

echo "Starting application..."
python app.py
