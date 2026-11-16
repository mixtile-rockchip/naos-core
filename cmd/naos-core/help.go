package main

import (
	"fmt"
	"io"
	"strings"

	"naos.local/core/internal/config"
)

func runCommand(args []string, out, stderr io.Writer) int {
	options, err := parseCommand(args)
	if err != nil {
		// flag errors can contain credentials or arbitrary supplied values.
		fmt.Fprintln(stderr, "naos-core: invalid arguments; see command usage below")
		printHelp(out, options.command)
		return 2
	}
	if options.help || options.command == "" || options.command == "hawkbit" {
		printHelp(out, options.command)
		return 0
	}
	if options.command == "hawkbit register" {
		// Manual registration never loads its inputs from the destination INI.
		return register(registrationOptions{server: options.server, tenant: options.tenant, token: options.token}, options.config, out, stderr)
	}
	cfg, err := config.Load(options.config)
	if err != nil {
		fmt.Fprintln(stderr, "naos-core:", err)
		return 1
	}
	switch options.command {
	case "serve":
		return serve(cfg, options.config, stderr)
	case "oem":
		return readOEM(cfg, out, stderr)
	case "boot-check":
		return checkBoot(cfg, out, stderr)
	case "hawkbit check":
		return checkHawkbit(cfg, options.config, out, stderr)
	case "hawkbit status":
		return call(cfg, "hawkbit", nil, "", out, stderr)
	case "containers", "containers list":
		return call(cfg, "containers", nil, "", out, stderr)
	case "containers start", "containers stop", "containers restart":
		return call(cfg, "containers", []string{strings.TrimPrefix(options.command, "containers "), options.args[0]}, "", out, stderr)
	case "update":
		return call(cfg, "update", options.args, options.requestID, out, stderr)
	case "task":
		return call(cfg, "task", options.args, "", out, stderr)
	default: // reboot, recovery, tasks
		return call(cfg, options.command, nil, "", out, stderr)
	}
}

// Help is built only when requested. A long-lived serve process does not create
// or retain a command tree, usage table or help-rendering state.
func printHelp(out io.Writer, topic string) bool {
	var purpose, arguments, description, children, localOptions string
	switch topic {
	case "":
		purpose = "Manage the NAOS device and its local Core service"
		arguments = "COMMAND [command options] [arguments]"
		description = "Device commands normally require sudo; the configuration contains credentials."
		children = `   serve       Run the Core service in the foreground (managed by OpenRC)
   oem         Read the device SN and MAC from supported OEM OTP
   boot-check  Run the configured boot check before OpenRC confirms the slot
   containers  List containers, or start, stop and restart one through naosd
   reboot      Request a device reboot
   recovery    Erase all userdata during the next boot and reboot
   update      Install a local signed RAUC bundle, or show current update progress
   tasks       List persistent update tasks
   task        Show one persistent update task by ID
   hawkbit     Register with hawkBit, inspect status or verify a token
`
	case "serve":
		purpose = "Run the Core service in the foreground (managed by OpenRC)"
	case "oem":
		purpose = "Read the device SN and MAC from supported OEM OTP"
		description = "Reads OTP only. Requires [platform] soc=rk3588; Core need not be running."
	case "boot-check":
		purpose = "Run the configured boot check before OpenRC confirms the slot"
		description = "With [boot] check_enabled=false, uses the basic system check. Otherwise check_program must exit 0 within 60 seconds. This command does not mark the slot good."
	case "containers":
		purpose = "List containers, or start, stop and restart one through naosd"
		arguments = "[COMMAND [ID]]"
		children = `   list     List the current containers (also the default without a subcommand)
   start    Deploy/start the named container
   stop     Stop the named container
   restart  Restart the named container
`
	case "containers list":
		purpose = "List the current containers"
	case "containers start":
		purpose, arguments = "Deploy/start the named container", "ID"
	case "containers stop":
		purpose, arguments = "Stop the named container", "ID"
	case "containers restart":
		purpose, arguments = "Restart the named container", "ID"
	case "reboot":
		purpose = "Request a device reboot"
	case "recovery":
		purpose = "Erase all userdata during the next boot and reboot"
		description = "Factory reset deletes overlay settings and application data on the mounted userdata filesystem."
	case "update":
		purpose = "Install a local signed RAUC bundle, or show current update progress"
		arguments = "[BUNDLE_PATH]"
		description = "Accepts signed system (rootfs + boot) and bootloader (uboot + idb) bundles. Installation continues after submission. Use task TASK_ID to follow it; Core automatically reboots after a verified successful installation. Bootloader updates keep the current system slot."
		localOptions = "   --request-id ID  Idempotency ID for a local update (requires BUNDLE_PATH)\n"
	case "tasks":
		purpose = "List persistent update tasks"
	case "task":
		purpose, arguments = "Show one persistent update task by ID", "TASK_ID"
	case "hawkbit":
		purpose = "Register with hawkBit, inspect status or verify a token"
		arguments = "COMMAND [command options]"
		children = `   status    Show heartbeat, updater state and recent logs from the running Core
   check     Make one authenticated DDI request using the configuration
   register  Register using explicit connection parameters and a fresh hardware-derived ID
`
	case "hawkbit status":
		purpose = "Show heartbeat, updater state and recent logs from the running Core"
	case "hawkbit check":
		purpose = "Make one authenticated DDI request using the configuration"
		description = "Works with Core stopped or hawkBit disabled; does not launch an updater."
	case "hawkbit register":
		purpose = "Register using explicit connection parameters and a fresh hardware-derived ID"
		arguments = "--server URL --tenant TENANT --token TOKEN"
		description = "Never reads registration inputs from INI. On success, saves and enables the profile in --config PATH, then applies it to the running Core without restarting the service. An active updater finishes before the new profile takes effect. A stopped Core uses it at next startup."
		localOptions = "   --server URL     hawkBit server origin URL (required)\n   --tenant TENANT  hawkBit tenant (required)\n   --token TOKEN    Shared GatewayToken (required)\n"
	default:
		return false
	}
	name := "naos-core"
	if topic != "" {
		name += " " + topic
	}
	fmt.Fprintf(out, "NAME:\n   %s - %s\n\nUSAGE:\n   %s [options]", name, purpose, name)
	if arguments != "" {
		fmt.Fprint(out, " ", arguments)
	}
	fmt.Fprint(out, "\n")
	if description != "" {
		fmt.Fprint(out, "\nDESCRIPTION:\n   ", description, "\n")
	}
	if children != "" {
		fmt.Fprint(out, "\nCOMMANDS:\n", children)
	}
	fmt.Fprint(out, "\nOPTIONS:\n", localOptions)
	fmt.Fprintf(out, "   --config PATH    Device INI; register saves here, other commands read it (default: %s)\n", config.DefaultPath)
	fmt.Fprint(out, "   --help, -h       Show command help\n\n   help, h [COMMAND]  Show help for this command or a subcommand\n")
	return true
}
