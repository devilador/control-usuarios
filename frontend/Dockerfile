# Usar la imagen base de Python
FROM python:3.12

# Establecer el directorio de trabajo en el contenedor
WORKDIR /app

# Copiar los archivos del frontend al contenedor
COPY . /app

# Instalar las dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Exponer el puerto donde correrá el frontend
EXPOSE 5001

# Comando para ejecutar la aplicación
CMD ["python", "app.py"]
