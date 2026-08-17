<?php

define('PHP_STAN', true);

function read_config_option(string $name): mixed {
	return null;
}

function cacti_log(string $message, bool $output = false, string $facility = ''): void {
}

function spikekill_version(): array {
	return ['version' => 'unknown'];
}
