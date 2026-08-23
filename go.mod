module github.com/refraction-networking/utls

go 1.26.6

retract (
	v1.4.1 // #218
	v1.4.0 // #218 panic on saveSessionTicket
)

require (
	github.com/andybalholm/brotli v1.2.0
	github.com/klauspost/compress v1.18.1
	golang.org/x/crypto v0.55.0
	golang.org/x/net v0.58.0
	golang.org/x/sys v0.47.0
)

require golang.org/x/text v0.41.0 // indirect
