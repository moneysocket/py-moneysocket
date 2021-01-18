FROM python:3.8

RUN apt update  && \
  apt install libsecp256k1-dev -y

COPY ./ /moneysocket

WORKDIR /moneysocket

RUN pip install -e .
