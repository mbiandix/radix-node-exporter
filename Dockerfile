# mbiandix/radix-node-exporter:$version

FROM python:3.8-slim-buster AS main
#

ARG RUN_DIR="/opt/node-exporter"

ENV ENV "production"
ENV LOG_LEVEL "info"
ENV RADIXDLT_NGINX_HOST "nginx"
ENV RADIXDLT_NGINX_PASSWD ""
ENV LISTEN_PORT 9111
ENV NODE_ID ""

WORKDIR $RUN_DIR
COPY requirements.txt .
COPY src ./src

# Install python modules
RUN pip install -r requirements.txt

# create the logs dir
RUN mkdir -p ${RUN_DIR}/logs

# Publish the webhook port
EXPOSE ${LISTEN_PORT}/tcp

# Start the App
CMD ./src/exporter.py --env=$ENV \
                      --dir="." \
                      --log-level=$LOG_LEVEL \
                      --passwd=$RADIXDLT_NGINX_PASSWD \
                      --port=$LISTEN_PORT \
                      --endpoint=$RADIXDLT_NGINX_HOST \
                      --id=$NODE_ID
