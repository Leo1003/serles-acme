FROM dockersource.cc.cs.nctu.edu.tw/devops/images/alpine/3.21

WORKDIR /usr/src/serles-acme

RUN apk add --no-cache \
    python3 \
    py3-pip \
    py3-cryptography \
    py3-requests \
    py3-flask \
    py3-flask-restful \
    py3-flask-sqlalchemy \
    py3-psycopg2 \
    py3-jwcrypto \
    py3-dnspython \
    py3-gunicorn
RUN pip3 install --no-cache-dir --break-system-packages \
    zeep

COPY . /usr/src/serles-acme

EXPOSE 8443

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8443", "--access-logfile", "-", "serles:create_app()"]
