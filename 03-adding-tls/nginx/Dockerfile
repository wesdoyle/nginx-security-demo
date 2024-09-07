FROM alpine:3.14

RUN apk add --no-cache nginx openssl

COPY conf.d/nginx.conf /etc/nginx/nginx.conf

RUN mkdir -p /etc/nginx/ssl

COPY generate_cert.sh /generate_cert.sh

RUN sh /generate_cert.sh

RUN mv nginx-selfsigned.crt nginx-selfsigned.key /etc/nginx/ssl/

EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]