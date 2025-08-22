from flask import Flask
from flask_login import LoginManager
from main import main
from banco import Usuario, criar_database_se_nao_existir, criar_tabelas
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from flask_mail import Mail

# Inicializa o Flask
app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'

# Configura o banco de dados
usuario = 'root'
senha = '12345678'
host = 'localhost'
banco = 'CondoIQ'
url = f"mysql+pymysql://{usuario}:{senha}@{host}/{banco}?charset=utf8mb4"
engine = create_engine(url, echo=True)
Session = sessionmaker(bind=engine)

# Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'main.login'

@login_manager.user_loader
def load_user(user_id):
    session = Session()
    try:
        return session.query(Usuario).get(int(user_id))
    finally:
        session.close()

# Configurações de email
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'tueursprimecs2@gmail.com'
app.config['MAIL_PASSWORD'] = 'sgoz cask wxad onsb'
app.config['MAIL_DEFAULT_SENDER'] = 'seuapp@gmail.com'

mail = Mail(app)
main.mail = mail  # injeta no blueprint

# 🔹 Aqui registra o blueprint
app.register_blueprint(main)

if __name__ == '__main__':
    criar_database_se_nao_existir()
    criar_tabelas()
    app.run(debug=True)