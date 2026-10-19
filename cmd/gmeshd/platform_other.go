//go:build !windows

package main

func serviceMain() bool { return false }

func defaultConfigPath() string { return "/etc/gmesh/config.yaml" }
