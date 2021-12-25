# This Dockerfile will do the following:
# - start a vuln docker container
# - copy the sCape tool into the container
# - will run the tool with the demo command "ls -la /" or other command
# - run the container with vuln permissions like so: docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash

# Get the base image
FROM ubuntu:16.04

# Install all packages
# RUN \

# apt-get update && \

# apt-get -y upgrade && \

# apt-get install -y apache2 && \

# adding some content for Apache server
# RUN echo "This is a test docker" > /var/www/html/index.html

# Copying setting file & adding some content to be served by apache
COPY sCape.sh /

# Defining a command to be run after the docker is up
ENTRYPOINT ["/bin/bash"]

# CMD ["scape.sh 'ls -la /'"]