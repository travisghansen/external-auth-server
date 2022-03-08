######################
# build image
######################
FROM node:16-bullseye AS build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y python

RUN mkdir -p /tmp/app
WORKDIR /tmp/app

COPY package*.json ./
RUN npm install
COPY . .

######################
# actual image
######################
FROM node:16-bullseye-slim

ENV DEBIAN_FRONTEND=noninteractive

# Run as a non-root user
RUN useradd --create-home eas \
        && mkdir /home/eas/app \
        && chown -R eas: /home/eas

COPY --from=build --chown=eas:eas /tmp/app /home/eas/app

# Remove obsolete files
RUN rm -rf /home/eas/app/examples \
        && rm -rf  /home/eas/app/.git* \
        && rm -rf /home/eas/app/.travis* \
        && rm -rf /home/eas/app/contrib \
        && rm -rf /home/eas/app/charts \
        && rm /home/eas/app/*.md

WORKDIR /home/eas/app
USER eas

EXPOSE 8080
ENTRYPOINT [ "npm", "run", "--silent"]
CMD [ "start" ]
