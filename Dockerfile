FROM --platform=linux/amd64 python:3.11-slim

WORKDIR /app
ENV DEBIAN_FRONTEND=noninteractive

# Configure Wireshark non-root execution pre-seed
RUN echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections

# Install System dependencies: CICFlowMeter (Java), XGBoost (libgomp1), tshark/dumpcap
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    default-jre-headless \
    tshark \
    tcpdump \
    wireshark-common \
    libcap2-bin \
    libpcap-dev \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Set binary execution permissions for raw packet capture
RUN if [ -f /usr/bin/dumpcap ]; then \
    setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap || true; \
    chmod +x /usr/bin/dumpcap || true; \
    fi

# Add wireshark group permissions
RUN usermod -aG wireshark root || true

# Install Python dependencies
COPY requirements.txt .
RUN grep -v "^xgboost==" requirements.txt > requirements-no-xgboost.txt && \
    pip install --no-cache-dir --prefer-binary --default-timeout=300 -r requirements-no-xgboost.txt && \
    pip install --no-cache-dir --prefer-binary --no-deps xgboost==3.2.0 && \
    rm requirements-no-xgboost.txt

# Copy CICFlowMeter dependency
COPY CICFlowMeter-master /app/CICFlowMeter-master
RUN chmod +x /app/CICFlowMeter-master/bin/* 2>/dev/null || true

# Copy main application code
COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]