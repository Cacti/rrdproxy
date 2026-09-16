<?php

define('PHP_STAN', true);

/**
 * PHPStan stub: Cacti's real settings-table accessor, unavailable outside a
 * Cacti install, so analysis always sees it return null here.
 */
function read_config_option(string $name): mixed {
	return null;
}

/**
 * PHPStan stub: Cacti's real logging function, unavailable outside a Cacti
 * install, so analysis sees a no-op here.
 */
function cacti_log(string $message, bool $output = false, string $facility = ''): void {
}

/**
 * PHPStan stub: the Spikekill plugin's real version accessor, unavailable
 * outside a Cacti install, so analysis always sees an 'unknown' version here.
 */
function spikekill_version(): array {
	return ['version' => 'unknown'];
}
