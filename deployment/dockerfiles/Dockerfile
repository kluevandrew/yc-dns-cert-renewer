FROM debian:stretch
ARG PROJECT_NAME
WORKDIR /$PROJECT_NAME

RUN apt-get update && apt-get install -y \
  ca-certificates \
  curl \
  wget \
  bash \
  iputils-ping \
  && rm -rf /var/lib/apt/lists/*

COPY ./build/ /$PROJECT_NAME
RUN chmod -R +x /$PROJECT_NAME
ENV PROJECT_NAME ${PROJECT_NAME}

CMD /$PROJECT_NAME/app/main
