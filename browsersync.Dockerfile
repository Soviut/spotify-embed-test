FROM node:14.15.1-alpine3.10

WORKDIR /src

RUN npm install -g browser-sync

EXPOSE 3000
EXPOSE 3001

ENTRYPOINT browser-sync --server --no-open --files \"*.html\"
