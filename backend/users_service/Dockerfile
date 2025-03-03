# Usa una imagen de Python optimizada
FROM python:3.12

# Establecer el directorio de trabajo
WORKDIR /app

# Copiar los archivos del servicio a la imagen
COPY . /app

# Instalar dependencias
RUN pip install --no-cache-dir -r requirements.txt

# Exponer el puerto en el contenedor
EXPOSE 8011

# Ejecutar la aplicación
CMD ["python", "app.py"]
