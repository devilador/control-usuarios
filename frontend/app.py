from flask import Flask, render_template, request, redirect, url_for, session
import os
import requests

app = Flask(__name__)
app.secret_key = 'JWT_SECRET_KEY'  
app.config["SESSION_TYPE"] = "filesystem"

# URL de los microservicios
AUTH_SERVICE_URL = "http://localhost:8010/auth/login"
USERS_SERVICE_URL = "http://localhost:8011/users"

# Página de login

@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        response = requests.post(AUTH_SERVICE_URL, json={"email": email, "password": password})

        if response.status_code == 200:
            data = response.json()
            session["token"] = data["token"]
            session["role"] = data["role"]

            print("TOKEN GUARDADO:", session["token"])  # 🔍 Verificar si se guarda el token

            return redirect(url_for("users"))  # 🔄 Redirigir a la página de usuarios
        else:
            error = "Credenciales inválidas"

    return render_template("login.html", error=error)


# Página de usuarios (requiere autenticación)
@app.route("/users")
def users():
    if "token" not in session:
        return redirect(url_for("login"))

    headers = {"Authorization": f"Bearer {session['token']}"}
    response = requests.get(USERS_SERVICE_URL, headers=headers)

    if response.status_code == 200:
        users_data = response.json()
        return render_template("users.html", users=users_data, role=session.get("role"))
    else:
        return redirect(url_for("login"))



    # Editar usuario
@app.route("/users/edit/<int:user_id>", methods=["GET", "POST"])
def edit_user(user_id):
    if "token" not in session:
        return redirect(url_for("login"))

    headers = {"Authorization": f"Bearer {session['token']}"}
    response = requests.get(f"{USERS_SERVICE_URL}/{user_id}", headers=headers)

    print(f"📌 Estado de /users/{user_id}: {response.status_code}")  # 🔍 Imprimir código de estado
    print(f"📌 Respuesta de /users/{user_id}: {response.text}")  # 🔍 Ver contenido de la respuesta

    try:
        user_data = response.json()
    except requests.exceptions.JSONDecodeError:
        print("❌ Error: No se pudo decodificar JSON. Verifica la respuesta del backend.")
        return redirect(url_for("users"))

    if request.method == "POST":
        new_data = {
            "username": request.form["username"],
            "email": request.form["email"],
            "role": request.form["role"]
        }
        requests.put(f"{USERS_SERVICE_URL}/{user_id}", json=new_data, headers=headers)
        return redirect(url_for("users"))

    return render_template("edit_user.html", user=user_data)

    
@app.route("/users/delete/<int:user_id>")
def delete_user(user_id):
    if "token" not in session:
        return redirect(url_for("login"))

    headers = {"Authorization": f"Bearer {session['token']}"}
    requests.delete(f"{USERS_SERVICE_URL}/{user_id}", headers=headers)
    return redirect(url_for("users"))


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        # Enviar datos al servicio de usuarios
        response = requests.post(f"{USERS_SERVICE_URL}/register", json={
            "username": username,
            "email": email,
            "password": password,
            "role": "user"  # Rol por defecto "user"
        })

        if response.status_code == 201:
            return redirect(url_for("login"))  # Redirigir al login después del registro
        else:
            error = response.json().get("message", "Error al registrar usuario")

    return render_template("register.html", error=error)


@app.route("/users/register", methods=["GET", "POST"])
def register_user():
    if "token" not in session:
        return redirect(url_for("login"))

    error = None
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        role = request.form["role"]

        headers = {"Authorization": f"Bearer {session['token']}"}
        response = requests.post(f"{USERS_SERVICE_URL}/register", json={
            "username": username,
            "email": email,
            "password": password,
            "role": role
        }, headers=headers)

        if response.status_code == 201:
            return redirect(url_for("users"))
        else:
            error = response.json().get("message", "Error al registrar usuario")

    return render_template("register_user.html", error=error)




    

    


# Cerrar sesión
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True, port=5001)
