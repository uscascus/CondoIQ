# main.py
from flask import Blueprint, render_template

main = Blueprint('main', __name__)

@main.route('/')
def home():
    # Isso renderiza o arquivo index.html que está na pasta 'templates'
    return render_template('index.html')