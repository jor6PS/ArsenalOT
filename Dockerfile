# Usar una imagen de Python oficial ligera
FROM python:3.11-slim

# Evitar que Python genere archivos .pyc y habilitar modo sin buffer para logs
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV PYTHONPATH /app/src

# Instalar dependencias del sistema necesarias
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    tshark \
    tcpdump \
    libpcap-dev \
    gcc \
    python3-dev \
    sudo \
    git \
    chromium \
    chromium-driver \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Configurar tshark para que pueda ser ejecutado por un usuario no root (aunque correremos como root para escaneos)
RUN groupadd -r wireshark && \
    usermod -aG wireshark root && \
    setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap

# Instalar EyeWitness (capturas web con Chromium)
RUN git clone --depth 1 https://github.com/FortyNorthSecurity/EyeWitness.git /opt/eyewitness \
    && pip install --no-cache-dir -r /opt/eyewitness/requirements.txt

# Variables de entorno para que EyeWitness localice Chromium
ENV CHROMIUM_FLAGS="--no-sandbox --disable-dev-shm-usage"

# Establecer el directorio de trabajo
WORKDIR /app

# Copiar el archivo de requerimientos e instalar dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el resto del código de la aplicación
COPY . .

# Asegurar permisos para los scripts
RUN chmod +x src/arsenal/scripts/*.py

# Exponer el puerto de la aplicación FastAPI
EXPOSE 8000

# Comando para iniciar la aplicación
CMD ["python3", "-m", "arsenal.web.app"]
