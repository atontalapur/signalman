# Built by GoReleaser (dockers_v2). The build context holds the compiled
# binaries for the target platform. The image is the daemon; the CLIs ship
# as release archives.
FROM gcr.io/distroless/static-debian12:nonroot
COPY signalman* /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/signalmand"]
