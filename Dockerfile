FROM python:3.13-slim
LABEL authors="sqkkyzx@outlook.com"

RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir --upgrade uv
RUN uv pip install --system --no-cache-dir --upgrade \
    httpx \
    colorama \
    playwright==1.54.0 \
    fastapi[all] \
    pycryptodome

RUN groupadd -r -g 1000 appuser && \
    mkdir -p /usr/src/myapp && \
    useradd -r -u 1000 -g appuser appuser && \
    chown -R appuser:appuser /usr/src/myapp

WORKDIR /usr/src/myapp
USER appuser
COPY --chown=appuser:appuser . .

EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]