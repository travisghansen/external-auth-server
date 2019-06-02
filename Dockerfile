FROM node:10

# Run as a non-root user
RUN useradd --create-home eas \
        && mkdir /home/eas/app \
        && chown -R eas: /home/eas
WORKDIR /home/eas/app
USER eas

COPY package*.json ./
RUN npm install

COPY --chown=eas:eas . .

EXPOSE 8080

CMD [ "npm", "start" ]
