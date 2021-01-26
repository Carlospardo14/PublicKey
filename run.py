# Se importan las bibliotecas Flask es un Framework nos permite crear aplicaciones WEb
from flask import Flask, render_template, request, redirect,url_for, send_file, after_this_request, current_app, flash
# ZipFile Y Os para manejar archivos y rutas 
import zipfile
import os
# Flask mysql y sqlalchemy para manejar SQL y conexiones
from flask_mysqldb import MySQL
from flask_sqlalchemy import SQLAlchemy
# Crypto para manejar algoritmos de Llave Publica en este caso RSA
from Crypto.PublicKey import RSA
# Del archivo forms importamos los formularios creados.
from forms import SignupForm, LoginForm, CreateForm, DownloadForm, AuthForm
# Flask Login para el control de acceso de los usuarios
from flask_login import LoginManager,current_user, login_user, logout_user, login_required

from werkzeug.urls import url_parse
# Imporante para prevenir archivos mailiciosos y cross site scripting
from werkzeug.utils import secure_filename


# Algunas variables necesarias para la App
# Carperta donde se suben los archivos
UPLOAD_FOLDER = 'UserFiles'
# Extensiones de archivo permitidas
ALLOWED_EXTENSIONS = {'txt', 'pem'}
app = Flask(__name__)
# Configuracion de SQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://CriptoAdmin:AdminPac26116.@localhost/criptografia'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db = SQLAlchemy(app)

# Importamos los modelos de Base de Datos del archivo models
from models import User

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'CriptoAdmin'
app.config['MYSQL_PASSWORD'] = 'AdminPac26116.'
app.config['MYSQL_DB'] = 'criptografia'
mysql = MySQL(app)

# Clave necesaria para el manejo de Login
app.config['SECRET_KEY']='Pac26116.'
login_manager = LoginManager()
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Ruta de Index
@app.route('/')
def index():
    # Si hay algun archivo Zip almacenado en Memoria lo Borramos
    filePath ='Keys.Zip'
    if os.path.exists(filePath):
        os.remove(filePath)
    # Renderizamos el template index.html
    return render_template("index.html")

# Funcion para saber si es un archivo con extension valida
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Ruta para Registrarse en el sistema
@app.route('/registro/', methods=["GET","POST"])
def registro():
    # Si el usuario ya esta loggeado lo regresa a la pantalla principal
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    # Cargamos el formulario de Registro
    form = SignupForm()
    error = None
    # Cuando se da click en enviar
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        # Creamos el usuario y lo guardamos
        user = User.get_by_email(email)
        if user is not None:
            error = f'El email {email} ya está siendo utilizado por otro usuario'
        else: 
            # Creamos el usuario y lo guardamos
            user = User(name=name, email=email)
            user.set_password(password)
            user.save()
            # Dejamos al usuario logueado
            login_user(user, remember=True)
            # En caso de que el usuario estuviera vistando otra pagina lo regresamos a esa pagina
            next_page = request.args.get('next', None)
            if not next_page or url_parse(next_page).netloc != '':
                # Caso contrario lo mandamos al inicio
                next_page = url_for('index')
            return redirect(next_page)
            # Se renderea el template 
    return render_template("registro.html", form=form)

# Manejo de Usuarios
@login_manager.user_loader
def load_user(user_id):
    # print(user_id)
    # print(User.get_by_id(int(user_id)))
    return User.get_by_id(int(user_id))

# Ruta para loggearse
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Si el usuario ya inicio sesion lo regresa al inicio
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    # Cargamos el formulario de inicio de sesion
    form = LoginForm()
    # Si se envia el formulario
    if form.validate_on_submit():
        # Obtenemos el usuario
        user = User.get_by_email(form.email.data)
        # Si las contraseña ingresada es igual a la ingresada y el usuario no es nulo
        if user is not None and user.check_password(form.password.data):
            # Inicia Sesion el usuario y lo deja con sesion
            login_user(user, remember=form.remember_me.data)
            # En caso de que el usuario estuviera vistando otra pagina lo regresamos a esa pagina
            next_page = request.args.get('next')
            # Caso contrario lo mandamos al inicio
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('index')
            return redirect(next_page)
    # Se renderea el template 
    return render_template('login.html', form=form)

# Ruta para crear un par de llaves
@app.route('/create', methods=['GET', 'POST'])
# Se requiere que el usuario tenga sesion para entrar a la creacion de llaves
@login_required
def create():
    user_id = current_user.id
    print(type(user_id))
    print(user_id)
    # Formulario de Creacion
    form = CreateForm()
    if form.validate_on_submit():
        # Passphrase del usuario
        secret_code = request.form['passphrase']
        # Generamos la Llave con una longitud de 2048
        key = RSA.generate(2048)
        # La exportamos, codificación de texto, realizada de acuerdo con RFC1421 / RFC1423
        encrypted_key = key.export_key(passphrase=secret_code, pkcs=8,protection="scryptAndAES128-CBC")
        # La guardamos en la carpeta privateKey y en el archivo privkey.pem 
        file_out = open("privateKey/privkey.pem", "wb")
        file_out.write(encrypted_key)
        file_out.close()
        # Hacemos lo mismo para llave publica
        public_key = key.publickey().export_key()
        llave = public_key.decode("utf-8")
        file_out = open("privateKey/publkey.pem", "wb")
        file_out.write(public_key)
        file_out.close()
        # Accedemos a la base de datos y en el id del usuario logeado ponemos la llave publica
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE users
            SET publicKey = %s
            WHERE id = %s
        """, (llave, user_id))
        mysql.connection.commit()
        # Redirigimos a la pagina de descarga
        return redirect(url_for('download'))
    return render_template('create.html', form=form)

# Ruta para descargar las llaves en un Zip
@app.route('/download',methods=['GET', 'POST'])
# Se requiere que el usuario tenga una sesion 
@login_required
def download():
    # Formulario de Descarga
    form = DownloadForm()
    # Rutas de los Archivos
    private = "privateKey/privkey.pem"
    public = "privateKey/publkey.pem"
    # Cuando se da click en descargar
    if form.validate_on_submit():
        # Creamos un archivo.zip
        zipf = zipfile.ZipFile('Keys.zip','w', zipfile.ZIP_DEFLATED)
        #Escribimos en el archivo todos los archivos en la carpeta privateKey
        for root,dirs, files in os.walk('privateKey/'):
            for file in files:
                zipf.write('privateKey/'+file)
        zipf.close()
        # Removemos los archivos del sistema
        os.remove(private)
        os.remove(public)
        # Adjuntamos el archivo en un Zip
        return send_file('Keys.zip',
                mimetype = 'zip',
                attachment_filename= 'Keys.zip',
                as_attachment = True)
    return render_template('download.html', form = form )

# Ruta para authenticarse
@app.route('/auth', methods=['GET', 'POST'])
# Inicio de Sesion Requerido
@login_required
def auth():
    # Variable para mostrar si es correcto o no el archivo
    global auth
    form = AuthForm()
    # Formulario de Inicio de Sesion
    if request.method == 'POST':
        email = form.email.data
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # Si el usuario no selecciona un archivo y tampoco el navegador muestra un mensaje
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        # Si hay un archivo y la extension es aceptada
        if file and allowed_file(file.filename):
            # Revisamos si el nombre es seguro
            filename = secure_filename(file.filename)
            # Salvamos el archivo en una carpeta temporal 
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            # Abrimos el archivo
            f= open(UPLOAD_FOLDER+"/"+filename)
            # Obtenemos la llave
            keyP = f.read()
            f.close()
            os.remove(UPLOAD_FOLDER+"/"+filename)
            # Conexion a SQL
            cur = mysql.connection.cursor()
            # Obtenemos la llave del usuario con su email
            sql ='''SELECT publicKey FROM users where email = %s '''
            cur.execute(sql, (email,))
            data = cur.fetchall()
            cur.close()
            # Si existe el campo de PublicKey
            try: 
                # Si el archivo que subio el usuario es igual a lo almacenado en la base de datos
                if keyP == data[0][0]:
                    
                    flash('La llave corresponde al usuario')
                # Si no es igual
                else: 
                   flash('La llave no corresponde al usuario')
            # Error en cas
            except IndexError:
                return ' no existe ese usuario o la llave no es de el usuario'
    return render_template('upload.html' , form = form)

# Ruta para cerrar sesión
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

print (auth)

# encoded_key = open(UPLOAD_FOLDER+"/"+"rsa_key.pem", "rb").read()
# key = RSA.import_key(encoded_key, passphrase="Pac26116.")
# private_key = key.export_key()
# file_out = open("private.pem", "wb")
# file_out.write(private_key)
# file_out.close()