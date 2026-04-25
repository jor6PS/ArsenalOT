# Usar una imagen de Python oficial ligera
FROM python:3.11-slim

# Evitar que Python genere archivos .pyc y habilitar modo sin buffer para logs
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV PYTHONPATH /app/src

# Instalar dependencias del sistema necesarias
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    arp-scan \
    gcc \
    python3-dev \
    sudo \
    git \
    wget \
    curl \
    xvfb \
    xauth \
    firefox-esr \
    chromium \
    chromium-driver \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Instalar geckodriver para Firefox
ENV GECKO_VERSION v0.36.0
RUN wget https://github.com/mozilla/geckodriver/releases/download/$GECKO_VERSION/geckodriver-$GECKO_VERSION-linux64.tar.gz \
    && tar -xzf geckodriver-$GECKO_VERSION-linux64.tar.gz \
    && mv geckodriver /usr/local/bin/ \
    && rm geckodriver-$GECKO_VERSION-linux64.tar.gz

# Instalar EyeWitness
RUN git clone https://github.com/FortyNorthSecurity/EyeWitness.git /opt/EyeWitness && \
    cd /opt/EyeWitness/setup && \
    # EyeWitness setup.sh installs many things, we use its requirements
    pip install --no-cache-dir -r requirements.txt && \
    ln -s /opt/EyeWitness/Python/EyeWitness.py /usr/bin/eyewitness && \
    chmod +x /usr/bin/eyewitness

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
