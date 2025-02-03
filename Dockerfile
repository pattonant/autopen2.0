FROM kalilinux/kali-rolling

# 设置工作目录
WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    nmap \
    nikto \
    sqlmap \
    metasploit-framework \
    bloodhound \
    mimikatz \
    && rm -rf /var/lib/apt/lists/*

# 复制项目文件
COPY . /app/

# 安装Python依赖
RUN pip3 install -r requirements.txt

# 添加PyTorch和Transformers
RUN pip3 install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu
RUN pip3 install transformers

# 设置环境变量
ENV PYTHONPATH=/app
ENV PATH="/app:${PATH}"

# 设置入口点
ENTRYPOINT ["python3", "autopentest.py"] 