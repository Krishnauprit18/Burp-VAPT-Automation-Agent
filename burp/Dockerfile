FROM eclipse-temurin:21-jre-jammy
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxext6 libxrender1 libxtst6 libxi6 libx11-6 libxrandr2 libxfixes3 \
    libxdamage1 libxcomposite1 libgtk-3-0 libnss3 libasound2 ca-certificates jq \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 burp
WORKDIR /opt/burp
COPY burpsuite_pro.jar /opt/burp/burpsuite_pro.jar
COPY project-options.json /opt/burp/project-options.json
COPY user-options.json /opt/burp/user-options.json
COPY start-burp.sh /opt/burp/start-burp.sh
RUN chmod +x /opt/burp/start-burp.sh && mkdir -p /opt/burp/extensions /artifacts && chown -R burp:burp /opt/burp /artifacts
USER burp
ENTRYPOINT ["/opt/burp/start-burp.sh"]
