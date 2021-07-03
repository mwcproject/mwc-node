FROM rust:latest

# Prevent prompts
RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections

RUN apt -y update && apt -y upgrade

RUN apt -y install curl

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

RUN apt -y install build-essential cmake git libgit2-dev clang libncurses5-dev libncursesw5-dev locales zlib1g-dev pkg-config libssl-dev llvm

WORKDIR /root

RUN git clone https://github.com/mwcproject/mwc-node.git

WORKDIR /root/mwc-node

RUN cargo build --release

RUN cp target/release/mwc /usr/bin

# Set the locale
RUN sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && \
    locale-gen

ENV LANG=en_US.UTF-8

ENTRYPOINT ["/usr/bin/mwc"]

