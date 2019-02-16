# This dockerfile is meant to cross compile with a x64 machine for a mips host
# It is using multi stage build: 
# * builder: Cross compile c-lightning dependencies, then c-lightning itself with static linking
# * final: Copy the binaries required at runtime
# The resulting image uploaded to dockerhub will only contain what is needed for runtime.
# From the root of the repository, run "docker build -t yourimage:yourtag -f contrib/linuxmips.Dockerfile ."

FROM debian:stretch-slim as builder

ENV LIGHTNINGD_VERSION=master
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates autoconf automake build-essential git libtool python python3 wget gnupg dirmngr git \
  libc6-mips-cross gcc-mips-linux-gnu g++-mips-linux-gnu qemu qemu-user-static qemu-user binfmt-support

ENV target_host=mips-linux-gnu

ENV AR=${target_host}-ar \
AS=${target_host}-as \
CC=${target_host}-gcc \
CXX=${target_host}-g++ \
LD=${target_host}-ld \
STRIP=${target_host}-strip \
QEMU_LD_PREFIX=/usr/${target_host} \
MAKE_HOST=${target_host} \
HOST=${target_host}

RUN wget -q https://zlib.net/zlib-1.2.11.tar.gz \
&& tar xvf zlib-1.2.11.tar.gz \
&& cd zlib-1.2.11 \
&& ./configure --prefix=$QEMU_LD_PREFIX \
&& make \
&& make install && cd .. && rm zlib-1.2.11.tar.gz && rm -rf zlib-1.2.11

RUN apt-get install -y --no-install-recommends unzip tclsh \
&& wget -q https://www.sqlite.org/2018/sqlite-src-3260000.zip \
&& unzip sqlite-src-3260000.zip \
&& cd sqlite-src-3260000 \
&& ./configure --enable-static --disable-readline --disable-threadsafe --disable-load-extension --host=${target_host} --prefix=$QEMU_LD_PREFIX \
&& make \
&& make install && cd .. && rm sqlite-src-3260000.zip && rm -rf sqlite-src-3260000

RUN wget -q https://gmplib.org/download/gmp/gmp-6.1.2.tar.xz \
&& tar xvf gmp-6.1.2.tar.xz \
&& cd gmp-6.1.2 \
&& ./configure --disable-assembly --prefix=$QEMU_LD_PREFIX --host=${target_host} \
&& make \
&& make install && cd .. && rm gmp-6.1.2.tar.xz && rm -rf gmp-6.1.2

WORKDIR /opt/lightningd
COPY . .
ARG DEVELOPER=0
RUN ./configure --enable-static && make -j3 DEVELOPER=${DEVELOPER} && cp lightningd/lightning* cli/lightning-cli /usr/bin/

FROM debian:stretch-slim as final
COPY --from=builder /usr/bin/qemu-mips-static /usr/bin/qemu-mips-static
RUN apt-get update && apt-get install -y --no-install-recommends socat inotify-tools \
    && rm -rf /var/lib/apt/lists/* 

ENV LIGHTNINGD_DATA=/root/.lightning
ENV LIGHTNINGD_PORT=9835

RUN mkdir $LIGHTNINGD_DATA && \
    touch $LIGHTNINGD_DATA/config
VOLUME [ "/root/.lightning" ]

COPY --from=builder /opt/lightningd/cli/lightning-cli /usr/bin
COPY --from=builder /opt/lightningd/lightningd/lightning* /usr/bin/
COPY tools/docker-entrypoint.sh entrypoint.sh

EXPOSE 9735 9835
ENTRYPOINT  [ "./entrypoint.sh" ]
