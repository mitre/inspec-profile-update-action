# This dockerfile checks out a branch before installing the SAF CLI
ARG CACHEBUST=1
FROM node:lts-alpine as builder

ARG branch=delta

LABEL name="inspec-profile-update-action" \
      vendor="The MITRE Corporation" \
      version="${SAF_VERSION}" \
      release="1" \
      url="https://github.com/mitre/inspec-profile-update-action" \
      description="The MITRE Security Automation Framework (SAF) InSpec profile update action automates the process of updating profiles based on newer versions of benchmarks." \
      docs="https://github.com/mitre/inspec-profile-update-action" \
      run="docker run -d --name ${NAME} ${IMAGE} <args>"

WORKDIR /build
RUN apk add git
RUN git clone https://github.com/mitre/saf.git /build
WORKDIR /build
RUN git checkout $branch
RUN npm install --omit=dev
RUN yarn pack --install-if-needed --prod --filename saf.tgz

FROM node:lts-alpine

COPY --from=builder /build/saf.tgz /build/
RUN npm install -g /build/saf.tgz

# Copies your code file from your action repository to the filesystem path `/` of the container
COPY entrypoint.sh /entrypoint.sh

# Useful for CI pipelines
RUN apk add bash jq curl ca-certificates

# Code file to execute when the docker container starts up (`entrypoint.sh`)
ENTRYPOINT ["/entrypoint.sh"]
