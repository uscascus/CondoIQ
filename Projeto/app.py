from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from sqlalchemy import create_engine, or_
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from sqlalchemy_utils import database_exists, create_database
import bcrypt
import re
import secrets
import datetime
from sqlalchemy import Column, Integer, String, Date, ForeignKey, Table, Boolean

# Configurações do Banco de Dados e Modelos
usuario = 'root'
senha = '12345678'
host = 'localhost'
banco = 'CondoIQ'
url = f"mysql+pymysql://{usuario}:{senha}@{host}/{banco}?charset=utf8mb4"

engine = create_engine(url, echo=True)
Session = sessionmaker(bind=engine)
Base = declarative_base()

# Tabela de associação para o relacionamento N:M entre Usuario e Reuniao
reuniao_participantes = Table(
    'reuniao_participantes', Base.metadata,
    Column('usuario_id', Integer, ForeignKey('usuarios.id'), primary_key=True),
    Column('reuniao_id', Integer, ForeignKey('reunioes.id'), primary_key=True)
)

# Constantes para a tipagem do usuário
TIPO_SINDICO = 0
TIPO_MORADOR = 1

class Usuario(Base):
    __tablename__ = "usuarios"
    id = Column(Integer, primary_key=True)
    nome = Column(String(100), nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    senha = Column(String(255), nullable=False)
    tipo = Column(Integer, default=TIPO_MORADOR)
    condominio_id = Column(Integer, ForeignKey("condominio.id"), nullable=True)
    verification_code = Column(String(10), nullable=True)
    is_ativo = Column(Boolean, default=True, nullable=False)

    condominio = relationship("Condominio", back_populates="usuarios")
    reunioes = relationship("Reuniao", secondary=reuniao_participantes, back_populates="participantes")

    def is_authenticated(self): return True
    def is_active(self): return self.is_ativo
    def is_anonymous(self): return False
    def get_id(self): return str(self.id)

class Condominio(Base):
    __tablename__ = "condominio"
    id = Column(Integer, primary_key=True)
    nome = Column(String(150), nullable=False)
    endereco = Column(String(255), nullable=False)
    cnpj = Column(String(18), unique=True, nullable=True)
    telefone = Column(String(20), nullable=True)
    email = Column(String(100), nullable=True)
    data_cadastro = Column(Date, default=datetime.date.today)
    status = Column(String(50), default="pendente")
    usuarios = relationship("Usuario", back_populates="condominio")
    despesas = relationship("Despesa", back_populates="condominio")
    reunioes = relationship("Reuniao", back_populates="condominio")

class Despesa(Base):
    __tablename__ = "despesas"
    id = Column(Integer, primary_key=True)
    descricao = Column(String(255), nullable=False)
    valor = Column(Integer, nullable=False)
    data = Column(Date, nullable=False)
    categoria = Column(String(50), nullable=False)
    condominio_id = Column(Integer, ForeignKey("condominio.id"))
    condominio = relationship("Condominio", back_populates="despesas")

class Reuniao(Base):
    __tablename__ = "reunioes"
    id = Column(Integer, primary_key=True)
    titulo = Column(String(150), nullable=False)
    data = Column(Date, nullable=False)
    local = Column(String(255), nullable=False)
    condominio_id = Column(Integer, ForeignKey("condominio.id"))
    condominio = relationship("Condominio", back_populates="reunioes")
    participantes = relationship("Usuario", secondary=reuniao_participantes, back_populates="reunioes")

def criar_database_se_nao_existir():
    if not database_exists(engine.url):
        create_database(engine.url)

def criar_tabelas():
    Base.metadata.create_all(engine)

# -------------------------------------------------------------
# Configuração do Flask
app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'

# Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    session_db = Session()
    try:
        return session_db.query(Usuario).get(int(user_id))
    finally:
        session_db.close()

# Configurações de email
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'tueursprimecs2@gmail.com'
app.config['MAIL_PASSWORD'] = 'sgoz cask wxad onsb'
app.config['MAIL_DEFAULT_SENDER'] = 'seuapp@gmail.com'
mail = Mail(app)

# -------------------------------------------------------------
# Rotas
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    step = request.values.get('step')
    session_db = Session()
    if request.method == 'POST':
        nome = request.form.get('nome')
        email = request.form.get('email')
        senha = request.form.get('senha')
        codigo = request.form.get('codigo')
        try:
            if step != 'verify':
                if not nome or not email or not senha:
                    flash('Todos os campos são obrigatórios!', 'error')
                    return redirect(url_for('register'))
                if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                    flash('Email inválido!', 'error')
                    return redirect(url_for('register'))
                if len(senha) < 8:
                    flash('A senha deve ter pelo menos 8 caracteres!', 'error')
                    return redirect(url_for('register'))
                if session_db.query(Usuario).filter_by(email=email).first():
                    flash('Email já cadastrado!', 'error')
                    return redirect(url_for('register'))
                
                # --- Lógica de envio de e-mail e salvamento de sessão ---
                verification_code = secrets.token_hex(3)
                session['verification_code'] = verification_code
                session['pending_registration'] = {'nome': nome, 'email': email, 'senha': senha}
                msg = Message('Código de Verificação - CondoIQ',
                              recipients=[email],
                              body=f'Seu código de verificação é: {verification_code}')
                if mail:
                    mail.send(msg)
                flash('Um código de verificação foi enviado para o seu email. Insira-o para confirmar.', 'success')
                return redirect(url_for('register', step='verify'))
            else:
                # --- Lógica de verificação do código ---
                if not codigo or codigo != session.get('verification_code'):
                    flash('Código de verificação inválido!', 'error')
                    return redirect(url_for('register', step='verify'))
                
                # --- Lógica de registro final ---
                hashed_senha = bcrypt.hashpw(session['pending_registration']['senha'].encode('utf-8'), bcrypt.gensalt())
                condominio_existente = session_db.query(Condominio).first()
                if not condominio_existente:
                    novo_usuario = Usuario(
                        nome=session['pending_registration']['nome'],
                        email=session['pending_registration']['email'],
                        senha=hashed_senha.decode('utf-8'),
                        tipo=TIPO_SINDICO
                    )
                    condominio_inicial = Condominio(
                        nome="Condomínio Padrão",
                        endereco="Endereço Padrão",
                        status="ativo"
                    )
                    session_db.add(condominio_inicial)
                    novo_usuario.condominio = condominio_inicial
                else:
                    novo_usuario = Usuario(
                        nome=session['pending_registration']['nome'],
                        email=session['pending_registration']['email'],
                        senha=hashed_senha.decode('utf-8'),
                        tipo=TIPO_MORADOR
                    )
                    novo_usuario.condominio = condominio_existente
                session_db.add(novo_usuario)
                session_db.commit()
                del session['verification_code']
                del session['pending_registration']
                flash('Registro concluído com sucesso! Faça login.', 'success')
                return redirect(url_for('login'))
        except Exception as e:
            session_db.rollback()
            flash(f'Erro ao processar registro: {str(e)}', 'error')
            return redirect(url_for('register', step=step))
        finally:
            session_db.close()
    
    # --- AQUI ESTÁ A MUDANÇA IMPORTANTE ---
    if step == 'verify':
        return render_template('verify.html')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identificador = request.form.get('identificador')
        senha = request.form.get('senha')
        session_db = Session()
        try:
            usuario = session_db.query(Usuario).filter_by(email=identificador).first()
            if usuario and bcrypt.checkpw(senha.encode('utf-8'), usuario.senha.encode('utf-8')) and usuario.is_ativo:
                login_user(usuario)
                flash('Login realizado com sucesso!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Credenciais inválidas ou conta desativada!', 'error')
                return redirect(url_for('login'))
        finally:
            session_db.close()
    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
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
                    return redirect(url_for('forgot_password'))
                reset_code = secrets.token_hex(3)
                session['reset_code'] = reset_code
                session['reset_email'] = email
                msg = Message('Código de Redefinição de Senha - CondoIQ',
                              recipients=[email],
                              body=f'Seu código de redefinição de senha é: {reset_code}')
                if mail:
                    mail.send(msg)
                flash('Um código de redefinição foi enviado para o seu email. Insira-o para continuar.', 'success')
                return redirect(url_for('forgot_password', step='verify'))
            elif step == 'verify':
                codigo = request.form.get('codigo')
                email_session = session.get('reset_email')
                if not email_session:
                    flash('Sessão expirada. Tente novamente.', 'error')
                    return redirect(url_for('forgot_password'))
                if not codigo or codigo != session.get('reset_code'):
                    flash('Código de redefinição inválido!', 'error')
                    return redirect(url_for('forgot_password', step='verify'))
                flash('Código verificado com sucesso. Agora insira sua nova senha.', 'success')
                return redirect(url_for('forgot_password', step='reset'))
            elif step == 'reset':
                nova_senha = request.form.get('nova_senha')
                email_session = session.get('reset_email')
                if not email_session:
                    flash('Sessão expirada. Tente novamente.', 'error')
                    return redirect(url_for('forgot_password'))
                if len(nova_senha) < 8:
                    flash('A nova senha deve ter pelo menos 8 caracteres!', 'error')
                    return redirect(url_for('forgot_password', step='reset'))
                usuario = session_db.query(Usuario).filter_by(email=email_session).first()
                hashed_senha = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt())
                usuario.senha = hashed_senha.decode('utf-8')
                session_db.commit()
                del session['reset_code']
                del session['reset_email']
                flash('Senha redefinida com sucesso! Faça login com a nova senha.', 'success')
                return redirect(url_for('login'))
        except Exception as e:
            session_db.rollback()
            flash(f'Erro ao processar recuperação: {str(e)}. Verifique suas configurações de email.', 'error')
            return redirect(url_for('forgot_password', step=step))
        finally:
            session_db.close()
    return render_template('forgot_password.html', step=step)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você saiu da sua conta.', 'success')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    session_db = Session()
    try:
        usuario_ativo = session_db.query(Usuario).get(current_user.id)
        if usuario_ativo and usuario_ativo.condominio:
            condominio = usuario_ativo.condominio
            return render_template('dashboard.html', condominio=condominio, user=usuario_ativo, TIPO_SINDICO=TIPO_SINDICO)
        else:
            return render_template('no_condominio.html', user=usuario_ativo)
    except Exception as e:
        flash(f'Ocorreu um erro: {e}', 'error')
        return redirect(url_for('home'))
    finally:
        session_db.close()

@app.route('/gerenciar_moradores')
@login_required
def gerenciar_moradores():
    session_db = Session()
    try:
        usuario_ativo = session_db.query(Usuario).get(current_user.id)
        if usuario_ativo.tipo != TIPO_SINDICO:
            flash("Você não tem permissão para acessar esta página.", "error")
            return redirect(url_for('dashboard'))
        moradores = session_db.query(Usuario).filter(
            Usuario.condominio_id == usuario_ativo.condominio_id,
            Usuario.id != usuario_ativo.id
        ).all()
        return render_template('gerenciar_moradores.html', moradores=moradores, user=usuario_ativo)
    except Exception as e:
        flash(f'Ocorreu um erro: {e}', 'error')
        return redirect(url_for('home'))
    finally:
        session_db.close()
        
# --- Rotas para teste de sessão (Remova após o teste) ---
@app.route('/set_test_session')
def set_test_session():
    session['teste'] = 'sessao_funcionando'
    flash('Um valor foi salvo na sua sessão!', 'success')
    return redirect(url_for('home'))

@app.route('/get_test_session')
def get_test_session():
    valor = session.get('teste')
    if valor:
        flash(f'O valor na sessão é: {valor}', 'success')
    else:
        flash('Não foi possível encontrar o valor na sessão.', 'error')
    return redirect(url_for('home'))
# --------------------------------------------------------

if __name__ == '__main__':
    criar_database_se_nao_existir()
    criar_tabelas()
    app.run(debug=True)