# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.202.5/containers/python-3/.devcontainer/base.Dockerfile

# [Choice] Python version (use -bullseye variants on local arm64/Apple Silicon): 3, 3.10, 3.9, 3.8, 3.7, 3.6, 3-bullseye, 3.10-bullseye, 3.9-bullseye, 3.8-bullseye, 3.7-bullseye, 3.6-bullseye, 3-buster, 3.10-buster, 3.9-buster, 3.8-buster, 3.7-buster, 3.6-buster
ARG VARIANT="3.10-bullseye"
FROM mcr.microsoft.com/vscode/devcontainers/python:0-${VARIANT}

# [Choice] Node.js version: none, lts/*, 16, 14, 12, 10
ARG NODE_VERSION="none"
RUN if [ "${NODE_VERSION}" != "none" ]; then su vscode -c "umask 0002 && . /usr/local/share/nvm/nvm.sh && nvm install ${NODE_VERSION} 2>&1"; fi

COPY library-scripts/*.sh /tmp/library-scripts/

# [Choice] Ansible version: latest, 4.7.0, 4.6.0, 4.5.0, 4.4.0, 4.3.0, 4.2.0, 4.1.0, 4.0.0, 3.4.0, 3.3.0, 3.2.0, 3.1.0, 3.0.0, 2.10.7, 2.10.6, 2.10.5, 2.10.4, 2.10.3, 2.10.2, 2.10.1, 2.10.0, 2.9.27, 2.9.26, 2.9.25, 2.9.24, 2.9.23, 2.9.22, 2.9.21, 2.9.20, 2.9.19, 2.9.18, 2.9.17, 2.9.16, 2.9.15, 2.9.14, 2.9.13, 2.9.12, 2.9.11, 2.9.10, 2.9.9, 2.9.8, 2.9.7, 2.9.6, 2.9.5, 2.9.4, 2.9.3, 2.9.2, 2.9.1, 2.9.0, 2.8.20, 2.8.19, 2.8.18, 2.8.17, 2.8.16, 2.8.15, 2.8.14, 2.8.13, 2.8.12, 2.8.11, 2.8.10, 2.8.9, 2.8.8, 2.8.7, 2.8.6, 2.8.5, 2.8.4, 2.8.3, 2.8.2, 2.8.1, 2.8.0, 2.7.18, 2.7.17, 2.7.16, 2.7.15, 2.7.14, 2.7.13, 2.7.12, 2.7.11, 2.7.10, 2.7.9, 2.7.8, 2.7.7, 2.7.6, 2.7.5, 2.7.4, 2.7.3, 2.7.2, 2.7.1, 2.7.0, 2.6.20, 2.6.19, 2.6.18, 2.6.17, 2.6.16, 2.6.15, 2.6.14, 2.6.13, 2.6.12, 2.6.11, 2.6.10, 2.6.9, 2.6.8, 2.6.7, 2.6.6, 2.6.5, 2.6.4, 2.6.3, 2.6.2, 2.6.1, 2.6.0, 2.5.15, 2.5.14, 2.5.13, 2.5.12, 2.5.11, 2.5.10, 2.5.9, 2.5.8, 2.5.7, 2.5.6, 2.5.5, 2.5.4, 2.5.3, 2.5.2, 2.5.1, 2.5.0, 2.4.6.0, 2.4.5.0, 2.4.4.0, 2.4.3.0, 2.4.2.0, 2.4.1.0, 2.4.0.0, 2.3.3.0, 2.3.2.0, 2.3.1.0, 2.3.0.0, 2.2.3.0, 2.2.2.0, 2.2.1.0, 2.2.0.0, 2.1.6.0, 2.1.5.0, 2.1.4.0, 2.1.3.0, 2.1.2.0, 2.1.1.0, 2.1.0.0, 2.0.2.0, 2.0.1.0, 2.0.0.2, 2.0.0.1, 2.0.0.0, 1.9.6, 1.9.5, 1.9.4, 1.9.3, 1.9.2, 1.9.1, 1.9.0.1, 1.8.4, 1.8.3, 1.8.2, 1.8.1, 1.8, 1.7.2, 1.7.1, 1.7, 1.6.10, 1.6.9, 1.6.8, 1.6.7, 1.6.6, 1.6.5, 1.6.4, 1.6.3, 1.6.2, 1.6.1, 1.6, 1.5.5, 1.5.4, 1.5.3, 1.5.2, 1.5.1, 1.5, 1.4.5, 1.4.4, 1.4.3, 1.4.2, 1.4.1, 1.4, 1.3.4, 1.3.3, 1.3.2, 1.3.1, 1.3.0, 1.2.3, 1.2.2, 1.2.1, 1.2, 1.1, 1.0
ARG ANSIBLE_VERSION=latest
# [Choice] molecule version: latest, 3.5.2, 3.5.1, 3.4.1, 3.4.0, 3.3.4, 3.3.3, 3.3.2, 3.3.1, 3.3.0, 3.2.4, 3.2.3, 3.2.2, 3.2.1, 3.2.0, 3.1.5, 3.1.4, 3.1.3, 3.1.2, 3.1.1, 3.1.0, 3.0.8, 3.0.7, 3.0.6, 3.0.5, 3.0.4, 3.0.3, 3.0.2.1, 3.0.2, 3.0.1, 3.0.0, 2.22, 2.20.2, 2.20.1, 2.20.0, 2.19.0, 2.18.1, 2.18.0, 2.17.0, 2.16.0, 2.15.0, 2.14.0, 2.13.1, 2.13.0, 2.12.1, 2.12.0, 2.11.0, 2.10.1, 2.10.0, 1.25.1, 1.25.0, 1.23.0, 1.22.0, 1.21.1, 1.20.3, 1.20.1
ARG MOLECULE_VERSION=latest

RUN set -e; \
    ver_suffix(){ [ "${1#latest}" ] && echo "==$1";}; \
    # Unset DISPLAY so that pip does not give WSL2 a super high load.
    # see: https://stackoverflow.com/questions/68016708/on-wsl2-pip-install-virtualenv-comand-hangs-for-too-long
    DISPLAY=; \
    pip install --no-cache-dir -U pip; \
    pip install --no-cache-dir \
        "ansible$(ver_suffix ${ANSIBLE_VERSION})" \
        "molecule[docker,lint]$(ver_suffix ${MOLECULE_VERSION})"
