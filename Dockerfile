FROM alpine:3.20 AS build
RUN apk add --no-cache build-base linux-headers openssl-dev openssl-libs-static
WORKDIR /src
COPY Makefile .
COPY src ./src
RUN make

FROM scratch
COPY --from=build /src/build/absurd /absurd
COPY www /www
EXPOSE 8080
ENTRYPOINT ["/absurd"]
CMD ["/www"]
