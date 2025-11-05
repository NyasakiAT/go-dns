package main

import (
	"nyasaki/dns-server/dns"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	log.Info().Msg("Starting DNS")
	dns.StartServer()
}
