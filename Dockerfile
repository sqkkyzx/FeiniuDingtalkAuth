FROM python:3.13-slim
LABEL authors="sqkkyzx@outlook.com"

RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir --upgrade uv
RUN uv pip install --system --no-cache-dir --upgrade \
    httpx  \
    colorama  \
    playwright==1.54.0  \
    fastapi[all] \
    pycryptodome

WORKDIR /usr/src/myapp
COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
