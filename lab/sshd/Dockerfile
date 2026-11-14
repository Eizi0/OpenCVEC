# Cible de labo : serveur OpenSSH de la version fournie par la branche Alpine choisie.
ARG ALPINE=3.19
FROM alpine:${ALPINE}
RUN apk add --no-cache openssh-server && ssh-keygen -A
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
