@echo off
cd /d c:\Users\acer\Documents\CapStoneG10\Capstone_Backend
call venv\Scripts\activate.bat
pip install fastapi pydantic torch transformers sqlalchemy requests uvicorn psycopg2-binary aiosmtpd
uvicorn main:app --reload
pause
