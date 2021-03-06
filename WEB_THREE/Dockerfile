# Set the base image
FROM debian:latest

RUN apt-get update && apt-get install -y apache2 \
    libapache2-mod-wsgi \
    build-essential \
    python \
    python-dev\
    python-pip \
    vim \
    cowsay \
 && apt-get clean \
 && apt-get autoremove \
 && rm -rf /var/lib/apt/lists/*

# Copy over and install the requirements
COPY ./app/requirements.txt /var/www/apache-flask/app/requirements.txt
RUN pip install -r /var/www/apache-flask/app/requirements.txt

# Copy over the apache configuration file and enable the site
COPY ./apache-flask.conf /etc/apache2/sites-available/apache-flask.conf
RUN a2ensite apache-flask && \
    a2enmod headers

# Copy over the wsgi file
COPY ./apache-flask.wsgi /var/www/apache-flask/apache-flask.wsgi

COPY ./Dockerfile /var/www/apache-flask/app/static/Dockerfile
COPY ./app/routes.py /var/www/apache-flask/app/static/app.py
COPY ./flag.txt /flag.txt
COPY ./run.py /var/www/apache-flask/run.py
COPY ./app /var/www/apache-flask/app/

RUN a2dissite 000-default.conf && \
    a2ensite apache-flask.conf && \
    echo 'ulimit -v 148576' >> /etc/default/apache2

# LINK apache config to docker logs.
RUN ln -sf /proc/self/fd/1 /var/log/apache2/access.log && \
    ln -sf /proc/self/fd/1 /var/log/apache2/error.log && \
    chmod 444 /flag.txt && \
    chown root:root /flag.txt

EXPOSE 80

WORKDIR /var/www/apache-flask

CMD  /usr/sbin/apache2ctl -D FOREGROUND
