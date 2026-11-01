FROM alpine:3.20 AS build
RUN apk add --no-cache binutils make
WORKDIR /src
COPY Makefile .
COPY src ./src
RUN make

FROM scratch
COPY --from=build /src/build/absurd /absurd
EXPOSE 8080
ENTRYPOINT ["/absurd"]
