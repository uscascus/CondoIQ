from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from banco import Usuario
import bcrypt
from flask_login import login_user, logout_user, login_required, current_user
import re
import secrets
from flask_mail import Message

main = Blueprint('main', __name__)

# Configurações do banco
usuario = 'root'
senha = '12345678'
host = 'localhost'
banco = 'CondoIQ'
url = f"mysql+pymysql://{usuario}:{senha}@{host}/{banco}"
engine = create_engine(url)
Session = sessionmaker(bind=engine)

@main.route('/')
def home():
    return render_template('index.html')
@main.route('/register', methods=['GET', 'POST'])
def register():
    step = request.values.get('step')  # GET ou POST
    session_db = Session()

    if request.method == 'POST':
        nome = request.form.get('nome')
        email = request.form.get('email')
        senha = request.form.get('senha')
        codigo = request.form.get('codigo')

        try:
            # Primeiro passo: enviar código de verificação
            if step != 'verify':
                if not nome or not email or not senha:
                    flash('Todos os campos são obrigatórios!', 'error')
                    return redirect(url_for('main.register'))

                if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                    flash('Email inválido!', 'error')
                    return redirect(url_for('main.register'))

                if len(senha) < 8:
                    flash('A senha deve ter pelo menos 8 caracteres!', 'error')
                    return redirect(url_for('main.register'))

                if session_db.query(Usuario).filter_by(email=email).first():
                    flash('Email já cadastrado!', 'error')
                    return redirect(url_for('main.register'))

                verification_code = secrets.token_hex(3)
                session['verification_code'] = verification_code
                session['pending_registration'] = {'nome': nome, 'email': email, 'senha': senha}

                msg = Message('Código de Verificação - CondoIQ',
                              recipients=[email],
                              body=f'Seu código de verificação é: {verification_code}')
                main.mail.send(msg)
                flash('Um código de verificação foi enviado para o seu email. Insira-o para confirmar.', 'success')
                return redirect(url_for('main.register') + '?step=verify')

            # Segundo passo: validar código
            else:
                if not codigo or codigo != session.get('verification_code'):
                    flash('Código de verificação inválido!', 'error')
                    return redirect(url_for('main.register') + '?step=verify')

                hashed_senha = bcrypt.hashpw(session['pending_registration']['senha'].encode('utf-8'), bcrypt.gensalt())
                novo_usuario = Usuario(
                    nome=session['pending_registration']['nome'],
                    email=session['pending_registration']['email'],
                    senha=hashed_senha.decode('utf-8')
                )
                session_db.add(novo_usuario)
                session_db.commit()
                del session['verification_code']
                del session['pending_registration']
                flash('Registro concluído com sucesso! Faça login.', 'success')
                return redirect(url_for('main.login'))

        except Exception as e:
            session_db.rollback()
            flash(f'Erro ao processar registro: {str(e)}', 'error')
            return redirect(url_for('main.register'))
        finally:
            session_db.close()

    return render_template('register.html')


@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identificador = request.form.get('identificador')
        senha = request.form.get('senha')
        
        session_db = Session()
        try:
            usuario = session_db.query(Usuario).filter((Usuario.email == identificador) | (Usuario.nome == identificador)).first()
            
            if usuario and bcrypt.checkpw(senha.encode('utf-8'), usuario.senha.encode('utf-8')):
                login_user(usuario)
                flash('Login realizado com sucesso!', 'success')
                return redirect(url_for('main.home'))
            else:
                flash('Credenciais inválidas!', 'error')
                return redirect(url_for('main.login'))
        finally:
            session_db.close()
    
    return render_template('login.html')

@main.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    session_db = Session()
    step = request.args.get('step', 'send_code')

    if request.method == 'POST':
        try:
            if step == 'send_code':
                email = request.form.get('email')
                usuario = session_db.query(Usuario).filter_by(email=email).first()

                if not usuario:
                    flash('Email não encontrado!', 'error')
                    return redirect(url_for('main.forgot_password'))

                reset_code = secrets.token_hex(3)
                session['reset_code'] = reset_code
                session['reset_email'] = email

                msg = Message('Código de Redefinição de Senha - Sabores do Mundo',
                              recipients=[email],
                              body=f'Seu código de redefinição de senha é: {reset_code}')
                main.mail.send(msg)
                flash('Um código de redefinição foi enviado para o seu email. Insira-o para continuar.', 'success')
                return redirect(url_for('main.forgot_password', step='verify'))

            elif step == 'verify':
                codigo = request.form.get('codigo')
                email_session = session.get('reset_email')
                
                if not email_session:
                    flash('Sessão expirada. Tente novamente.', 'error')
                    return redirect(url_for('main.forgot_password'))

                if not codigo or codigo != session.get('reset_code'):
                    flash('Código de redefinição inválido!', 'error')
                    return redirect(url_for('main.forgot_password', step='verify'))

                flash('Código verificado com sucesso. Agora insira sua nova senha.', 'success')
                return redirect(url_for('main.forgot_password', step='reset'))
            
            elif step == 'reset':
                nova_senha = request.form.get('nova_senha')
                email_session = session.get('reset_email')
                
                if not email_session:
                    flash('Sessão expirada. Tente novamente.', 'error')
                    return redirect(url_for('main.forgot_password'))

                if len(nova_senha) < 8:
                    flash('A nova senha deve ter pelo menos 8 caracteres!', 'error')
                    return redirect(url_for('main.forgot_password', step='reset'))

                usuario = session_db.query(Usuario).filter_by(email=email_session).first()
                hashed_senha = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt())
                usuario.senha = hashed_senha.decode('utf-8')
                
                session_db.commit()
                del session['reset_code']
                del session['reset_email']
                flash('Senha redefinida com sucesso! Faça login com a nova senha.', 'success')
                return redirect(url_for('main.login'))

        except Exception as e:
            session_db.rollback()
            flash(f'Erro ao processar recuperação: {str(e)}. Verifique suas configurações de email.', 'error')
            # Retorna para o step atual para que o usuário possa tentar novamente
            return redirect(url_for('main.forgot_password', step=step))
        finally:
            session_db.close()
    
    return render_template('forgot_password.html', step=step)

@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você saiu da sua conta.', 'success')
    return redirect(url_for('main.home'))