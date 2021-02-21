FROM python:3.8.1-alpine3.11
LABEL maintainer=ghislain.bernard@gmail.com

WORKDIR /analyzer

COPY template template
RUN pip install --no-cache-dir --requirement template/requirements.txt

ENTRYPOINT ["template/template.py"]
