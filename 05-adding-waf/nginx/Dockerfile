# Use Debian as the base image for both stages
FROM debian:bullseye-slim AS builder

# Set environment variables
ENV NGINX_VERSION=1.19.3
ENV MODSEC_VERSION=3.0.8

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    libcurl4-openssl-dev \
    libgeoip-dev \
    liblmdb-dev \
    libpcre3-dev \
    libxml2-dev \
    libyajl-dev \
    pkgconf \
    wget \
    zlib1g-dev \
    libfuzzy-dev \
    libmaxminddb-dev \
    libpcre2-dev \
    autoconf \
    automake \
    libtool \
    libssl-dev

# Install SSDEEP from source
RUN wget https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz && \
    tar -xzvf ssdeep-2.14.1.tar.gz && \
    cd ssdeep-2.14.1 && \
    ./configure && \
    make && \
    make install && \
    ldconfig

# Install PCRE2 from source
RUN wget https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.39/pcre2-10.39.tar.gz && \
    tar -xzvf pcre2-10.39.tar.gz && \
    cd pcre2-10.39 && \
    ./configure --prefix=/usr && \
    make && \
    make install && \
    ldconfig

# Build ModSecurity
WORKDIR /root
RUN git clone --depth 1 -b v${MODSEC_VERSION} --single-branch https://github.com/SpiderLabs/ModSecurity && \
    cd ModSecurity && \
    git submodule init && \
    git submodule update && \
    ./build.sh && \
    ./configure --with-yajl --with-ssdeep=/usr/local --with-lmdb --with-geoip --with-pcre2=/usr --enable-silent-rules && \
    make && \
    make install

# Build Nginx with ModSecurity module
RUN wget http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && \
    tar zxvf nginx-${NGINX_VERSION}.tar.gz && \
    git clone -b master --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git && \
    cd nginx-${NGINX_VERSION} && \
    ./configure --prefix=/usr/local/nginx \
                --with-compat \
                --add-dynamic-module=../ModSecurity-nginx \
                --with-http_ssl_module && \
    make && \
    make install

# Final stage
FROM debian:bullseye-slim

# Set environment variables again for the final stage
ENV NGINX_VERSION=1.19.3
ENV MODSEC_VERSION=3.0.8

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libcurl4 \
    libmaxminddb0 \
    libxml2 \
    libyajl2 \
    liblmdb0 \
    moreutils \
    wget \
    libfuzzy2 \
    libpcre2-8-0 \
    libssl1.1 \
    libgeoip1 \
    && rm -rf /var/lib/apt/lists/*

# Copy Nginx, ModSecurity, and Nginx module
COPY --from=builder /usr/local/nginx /usr/local/nginx
COPY --from=builder /usr/local/modsecurity /usr/local/modsecurity
COPY --from=builder /usr/local/lib/libfuzzy.so* /usr/local/lib/
COPY --from=builder /usr/lib/libpcre2-8.so* /usr/lib/
COPY --from=builder /usr/lib/libGeoIP.so* /usr/lib/

# Set up environment
ENV PATH="/usr/local/nginx/sbin:${PATH}"

# Copy configuration files
COPY conf.d/nginx.conf /usr/local/nginx/conf/nginx.conf
COPY conf.d/main.conf /usr/local/nginx/conf/modsecurity/main.conf
COPY conf.d/ruleset.conf /usr/local/nginx/conf/modsecurity/ruleset.conf
COPY conf.d/modsecurity.conf /usr/local/nginx/conf/modsecurity/modsecurity.conf

# Set up ModSecurity
RUN mkdir -p /usr/local/nginx/conf/modsecurity
COPY --from=builder /root/ModSecurity/unicode.mapping /usr/local/nginx/conf/modsecurity/

# Set up OWASP Core Rule Set
RUN wget https://github.com/coreruleset/coreruleset/archive/v3.3.0.tar.gz && \
    tar -xvzf v3.3.0.tar.gz && \
    mv coreruleset-3.3.0 /usr/local/coreruleset && \
    cp /usr/local/coreruleset/crs-setup.conf.example /usr/local/coreruleset/crs-setup.conf && \
    rm v3.3.0.tar.gz


ENV LD_LIBRARY_PATH=/usr/local/modsecurity/lib:/usr/local/lib:/usr/lib:$LD_LIBRARY_PATH

# Create necessary directories and set permissions
RUN mkdir -p /tmp/modsecurity/data /tmp/modsecurity/upload /tmp/modsecurity/tmp && \
    mkdir -p /var/log/nginx && \
    chown -R www-data:www-data /tmp/modsecurity /usr/local/nginx /var/log/nginx

# Ensure www-data user exists
RUN useradd -r -s /sbin/nologin www-data || true
RUN useradd -r -s /sbin/nologin nginx || true

RUN mkdir -p /etc/nginx/ssl

COPY generate_cert.sh /generate_cert.sh

RUN sh /generate_cert.sh

RUN mv nginx-selfsigned.crt nginx-selfsigned.key /etc/nginx/ssl/

# Create symbolic link for ModSecurity logs
RUN mkdir -p /var/log/modsecurity
RUN ln -sf /dev/stdout /var/log/modsecurity/modsec_audit.log

EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]

HEALTHCHECK CMD curl --fail http://localhost || exit 1