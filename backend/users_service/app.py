from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)

# Configuración usando variables de entorno
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Modelo de Usuario
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')

# Crear la base de datos si no existe
with app.app_context():
    db.create_all()

# Registro de usuario
@app.route('/users/register', methods=['POST'])
def register_user():  # 🔄 Cambié "register" por "register_user"
    data = request.get_json()

    # Verificar si el usuario ya existe
    if User.query.filter_by(email=data["email"]).first():
        return jsonify({"message": "El correo ya está registrado"}), 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(
        username=data['username'],
        email=data['email'],
        password=hashed_password,
        role=data.get('role', 'user')  # Rol por defecto "user"
    )
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': 'Usuario registrado exitosamente'}), 201


# Obtener lista de usuarios
@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if user is None:
        return jsonify({'message': 'Usuario no encontrado'}), 404

    # TODOS los usuarios pueden ver la lista, pero solo los admins pueden editar/eliminar
    users = User.query.all()

    return jsonify([
        {
            'id': u.id,
            'username': u.username,
            'email': u.email,
            'role': u.role,
            'can_edit': user.role == 'admin'  # Permiso de edición solo para admins
        }
        for u in users
    ])






# Actualizar información del usuario (autorizado por roles)
@app.route('/users/<int:id>', methods=['PUT'])
@jwt_required()
def update_user(id):
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    # Verificar si el usuario existe
    user_to_update = User.query.get(id)
    if not user_to_update:
        return jsonify({'message': 'Usuario no encontrado'}), 404

    # Si no es admin, solo puede modificar su propio perfil
    if user.role != 'admin' and user_to_update.username != current_user:
        return jsonify({'message': 'No tienes permiso para modificar este usuario'}), 403

    data = request.get_json()
    if 'username' in data:
        user_to_update.username = data['username']
    if 'email' in data:
        user_to_update.email = data['email']
    if 'password' in data:
        user_to_update.password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    if 'role' in data and user.role == 'admin':  # Solo admins pueden cambiar roles
        user_to_update.role = data['role']

    db.session.commit()
    return jsonify({'message': 'Usuario actualizado exitosamente'})


# Eliminar usuario (solo administradores)
@app.route('/users/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_user(id):
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    # Verificar si el usuario es admin
    if user.role != 'admin':
        return jsonify({'message': 'No tienes permiso para eliminar usuarios'}), 403

    # Verificar si el usuario existe
    user_to_delete = User.query.get(id)
    if not user_to_delete:
        return jsonify({'message': 'Usuario no encontrado'}), 404

    db.session.delete(user_to_delete)
    db.session.commit()
    return jsonify({'message': 'Usuario eliminado exitosamente'})


#optener id
@app.route("/users/<int:id>", methods=["GET"])
@jwt_required()
def get_user(id):
    user = User.query.get(id)
    if not user:
        return jsonify({"message": "Usuario no encontrado"}), 404  # 🔍 Si no hay usuario, devolver error

    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role
    })





if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=8011)
