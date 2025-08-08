# app.py
from flask import Flask
from main import main # Importa o Blueprint 'main'

# Inicializa o aplicativo Flask
app = Flask(__name__)

# Registra o Blueprint no aplicativo
app.register_blueprint(main)

if __name__ == '__main__':
    # 'debug=True' é ótimo para desenvolvimento, pois reinicia o servidor
    # automaticamente quando você salva alguma alteração.
    app.run(debug=True)