# Bibliotecas del manejo de usuarios y de seguridad de las contraseñas.
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from run import db

# Creacion de las tablas 
class User(db.Model, UserMixin):

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(256), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    publicKey = db.Column(db.String(500), unique=True)
    
    def __repr__(self):
        return '<User {}>'.format(self.email)
# Codifica la contraseña
    def set_password(self, password):
        self.password = generate_password_hash(password)
# Verifica si el hash de las contraseñas son iguales
    def check_password(self, password):
        return check_password_hash(self.password, password)
# Agrega datos a la base de datos
    def save(self):
        if not self.id:
            db.session.add(self)
        db.session.commit()
# Obtener el usuario por id o por email
    @staticmethod
    def get_by_id(id):
        return User.query.get(id)
    @staticmethod
    def get_by_email(email):
        return User.query.filter_by(email=email).first()