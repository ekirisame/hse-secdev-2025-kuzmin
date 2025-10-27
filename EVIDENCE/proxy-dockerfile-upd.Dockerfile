FROM nginx:1.13-alpine
COPY conf /etc/nginx/conf.d/default.conf

RUN useradd -ms /bin/bash myuser
USER myuser