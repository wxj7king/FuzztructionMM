FROM ubuntu:22.04 as dev
ENV DEBIAN_FRONTEND noninteractive
ENV CCACHE_DIR=/ccache
ENV CCACHE_MAXSIZE=25G

RUN sed -i "s/^# deb-src/deb-src/g" /etc/apt/sources.list

RUN \
    apt update -y && apt install -y build-essential git cmake binutils-gold gosu sudo valgrind python3-pip wget \
    bison flex \
    zsh powerline fonts-powerline iputils-ping iproute2 ripgrep \
    libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev \
    ccache locales rr htop strace ltrace tree nasm \
    lsb-release ubuntu-dbgsym-keyring texinfo \
    neovim bear ccache locales rr htop strace \
    ltrace tree nasm lsb-release ubuntu-dbgsym-keyring gcc-multilib \
    linux-tools-generic \
    curl ninja-build xdot aspell-en neovim libgmp-dev tmux \
    man psmisc lsof rsync zip unzip qpdf ncdu fdupes parallel \
    texlive texlive-latex-extra texlive-fonts-recommended dvipng cm-super \
    virtualenv python2 g++ zlib1g-dev libc++-dev mercurial nano libssl-dev \
    lld llvm llvm-dev clang gcc-11-plugin-dev

RUN locale-gen en_US.UTF-8
ARG USER_UID=1000
ARG USER_GID=1000

#Enable sudo group
RUN echo "%sudo ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
WORKDIR /tmp

RUN update-locale LANG=en_US.UTF-8
ENV LANG=en_US.UTF-8

#Create user "user"
RUN groupadd -g ${USER_GID} user
# -l -> https://github.com/moby/moby/issues/5419
RUN useradd -l --shell /bin/bash -c "" -m -u ${USER_UID} -g user -G sudo user
WORKDIR "/home/user"

RUN echo "set speller \"aspell -x -c\"" > /etc/nanorc

USER user
RUN wget -O ~/.gdbinit-gef.py -q https://gef.blah.cat/py \
  && echo source ~/.gdbinit-gef.py >> ~/.gdbinit

# Install zsh
RUN sh -c "$(wget -O- https://raw.githubusercontent.com/deluan/zsh-in-docker/master/zsh-in-docker.sh)" -- \
    -t agnoster

# Install DynamoRIO
# RUN  wget https://github.com/DynamoRIO/dynamorio/releases/download/cronbuild-9.0.19078/DynamoRIO-Linux-9.0.19078.tar.gz && \
#      tar -xzvf DynamoRIO-Linux-9.0.19078.tar.gz && \
#      rm DynamoRIO-Linux-9.0.19078.tar.gz

USER user
