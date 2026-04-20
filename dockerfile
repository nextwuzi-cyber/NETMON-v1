# Используем Python 3.12 на базе Debian
FROM python:3.12-slim

# Устанавливаем системные зависимости
# libgl1 и libglx-mesa0 решают проблему с libGL.so.1
RUN apt-get update && apt-get install -y \
    nmap \
    libpcap-dev \
    libgl1 \
    libglx-mesa0 \
    libegl1 \
    libdbus-1-3 \
    libxkbcommon-x11-0 \
    libxcb-cursor0 \
    libxcb-icccm4 \
    libxcb-image0 \
    libxcb-keysyms1 \
    libxcb-render-util0 \
    libxcb-shape0 \
    libxcb-util1 \
    libxcb-xkb1 \
    libxcb-xinerama0 \
    libglib2.0-0 \
    libfontconfig1 \
    libxrender1 \
    libfreetype6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Копируем и ставим Python-зависимости
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем проект
COPY . .

# Переменные для графики
ENV QT_QPA_PLATFORM=xcb
ENV DISPLAY=:0

CMD ["python", "main.py"]