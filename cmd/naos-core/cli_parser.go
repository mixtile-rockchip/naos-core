package main

import (
	"errors"
	"flag"
	"io"
	"strings"

	"naos.local/core/internal/config"
)

type commandOptions struct {
	command, config, requestID string
	server, tenant, token      string
	args                       []string
	help                       bool
}

// parseCommand lets flag own names, values, booleans and errors. Walking one
// token at a time adds inherited/interspersed options to its usual parsing,
// without constructing a command tree for the service entry.
func parseCommand(args []string) (commandOptions, error) {
	options := commandOptions{config: config.DefaultPath}
	flags := flag.NewFlagSet("naos-core", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Usage = func() {}
	flags.StringVar(&options.config, "config", config.DefaultPath, "")
	flags.BoolVar(&options.help, "help", false, "")
	flags.BoolVar(&options.help, "h", false, "")
	invalid := errors.New("invalid command arguments")
	literal, helpCommand := false, false
	for i := 0; i < len(args); i++ {
		argument := args[i]
		if !literal && argument == "--" {
			literal = true
			continue
		}
		if !literal && strings.HasPrefix(argument, "-") && argument != "-" {
			name, _, hasValue := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(argument, "-"), "-"), "=")
			definition := flags.Lookup(name)
			if definition == nil {
				return options, invalid
			}
			values := []string{argument}
			boolean, isBool := definition.Value.(interface{ IsBoolFlag() bool })
			if !hasValue && !(isBool && boolean.IsBoolFlag()) {
				if i+1 == len(args) {
					return options, invalid
				}
				i++
				values = append(values, args[i])
			}
			if err := flags.Parse(values); err != nil {
				return options, invalid
			}
			continue
		}
		if !literal && len(options.args) == 0 && (argument == "help" || argument == "h") {
			helpCommand = true
			continue
		}
		switch options.command {
		case "":
			switch argument {
			case "serve", "oem", "containers", "reboot", "recovery", "update", "tasks", "task", "hawkbit", "boot-check":
				options.command = argument
			default:
				return options, invalid
			}
			if argument == "update" {
				flags.StringVar(&options.requestID, "request-id", "", "")
			}
		case "containers":
			switch argument {
			case "list", "start", "stop", "restart":
				options.command += " " + argument
			default:
				return options, invalid
			}
		case "hawkbit":
			switch argument {
			case "status", "check", "register":
				options.command += " " + argument
			default:
				return options, invalid
			}
			if argument == "register" {
				flags.StringVar(&options.server, "server", "", "")
				flags.StringVar(&options.tenant, "tenant", "", "")
				flags.StringVar(&options.token, "token", "", "")
			}
		default:
			if helpCommand {
				return options, invalid
			}
			options.args = append(options.args, argument)
		}
	}
	options.help = options.help || helpCommand
	if options.help {
		return options, nil
	}
	switch options.command {
	case "task", "containers start", "containers stop", "containers restart":
		if len(options.args) != 1 {
			return options, invalid
		}
	case "update":
		if len(options.args) > 1 || options.requestID != "" && len(options.args) == 0 {
			return options, invalid
		}
	default:
		if len(options.args) != 0 {
			return options, invalid
		}
	}
	return options, nil
}
