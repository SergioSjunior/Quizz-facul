from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import bcrypt

app = Flask(__name__)

# Funções para o banco de dados SQLite
def conectar_bd():
    return sqlite3.connect('usuarios.db')

def criar_tabela_usuarios():
    conn = conectar_bd()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            senha TEXT
        )
    ''')
    conn.commit()
    conn.close()

def adicionar_usuario(username, email, senha):
    conn = conectar_bd()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO usuarios (username, email, senha) VALUES (?, ?, ?)', (username, email, senha))
    conn.commit()
    conn.close()

def buscar_usuario_por_username(username):
    conn = conectar_bd()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM usuarios WHERE username = ?', (username,))
    usuario = cursor.fetchone()
    conn.close()
    return usuario

# Funções de autenticação
def validar_credenciais(username, password):
    usuario = buscar_usuario_por_username(username)
    if usuario:
        hash_senha = usuario[3]
        return verificar_senha(password, hash_senha)
    return False

def criar_hash_senha(senha):
    return bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt())

def verificar_senha(senha_digitada, hash_senha):
    return bcrypt.checkpw(senha_digitada.encode('utf-8'), hash_senha)

# Rotas Flask
@app.route('/')
def index():
    return 'Hello, World!'


#ROTA PARA PÁGINA DE LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if validar_credenciais(username, password):
            # Autenticação bem-sucedida, redirecionar para a home
            return redirect(url_for('home'))
        else:
            error = 'Credenciais inválidas. Tente novamente.'
            return render_template('login.html', error=error)
    return render_template('login.html')


#ROTA PÁGINA DE REGISTRO
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Verificar se o usuário já existe
        if buscar_usuario_por_username(username):
            error = 'Nome de usuário já está em uso. Por favor, escolha outro.'
            return render_template('register.html', error=error)
        
        # Verificar se a senha e a confirmação de senha são iguais
        if password != confirm_password:
            error = 'As senhas não coincidem. Por favor, tente novamente.'
            return render_template('register.html', error=error)
        
        # Criar hash da senha
        hashed_password = criar_hash_senha(password)
        
        # Adicionar o novo usuário ao banco de dados
        adicionar_usuario(username, email, hashed_password)
        
        # Redirecionar para a página de login após o registro bem-sucedido
        return redirect(url_for('login'))
    
    return render_template('register.html')

#ROTA PÁGINA INICIAL
@app.route('/home')
def home():
    # Renderiza o template da página inicial pós-login
    return render_template('home.html')

# Definindo o endpoint para iniciar um novo quiz
@app.route('/start_quiz')
def start_quiz():
    # Lógica para iniciar um novo quiz aqui
    # Por exemplo, você pode redirecionar para a página onde os usuários podem começar um quiz
    return redirect(url_for('quiz_start_page'))

# Definindo o endpoint para a página de início do quiz
@app.route('/quiz_start_page')
def quiz_start_page():
    return render_template('quiz_start_page.html')


if __name__ == '__main__':
    criar_tabela_usuarios()  # Criar a tabela de usuários ao iniciar o aplicativo
    app.run(debug=True)