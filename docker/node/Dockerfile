FROM node:14.21.3-alpine

RUN apk update
RUN apk add --no-cache python3 make g++
RUN adduser app --disabled-password

WORKDIR /home/app/src

EXPOSE 5683/udp

CMD [ "npm", "run", "echo" ]
