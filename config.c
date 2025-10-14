/*
 * QGP - Configuration File Support
 * Simple INI-style configuration parser for default settings
 *
 * Configuration file location: ~/.qgp/config
 * Format:
 *   # Comments start with #
 *   key = value
 *
 * Supported keys:
 *   default_key_name = <name>        # Default identity for signing/decryption
 *   default_algorithm = dilithium    # Default signature algorithm
 *   armor = yes|no                   # Default ASCII armor preference
 *   keyring_dir = <path>             # Custom keyring directory (default: ~/.qgp)
 */

#include "qgp.h"
#include "qgp_compiler.h"
#include <ctype.h>

#define MAX_LINE_LENGTH 1024
#define MAX_CONFIG_KEY 64
#define MAX_CONFIG_VALUE 512

// Global configuration structure
static qgp_config_t g_config = {
    .default_key_name = NULL,
    .default_algorithm = "dilithium",  // Default
    .armor_enabled = true,             // Default to ASCII armor
    .keyring_dir = NULL
};

// Trim whitespace from both ends of a string
static char* trim_whitespace(char *str) {
    char *end;

    // Trim leading space
    while (isspace((unsigned char)*str)) str++;

    if (*str == 0) return str;  // All spaces

    // Trim trailing space
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;

    // Null terminate
    *(end + 1) = 0;

    return str;
}

// Parse a boolean value (yes/no, true/false, 1/0)
static bool parse_bool(const char *value) {
    if (strcasecmp(value, "yes") == 0 ||
        strcasecmp(value, "true") == 0 ||
        strcmp(value, "1") == 0) {
        return true;
    }
    return false;
}

// Parse a single configuration line
static void parse_config_line(char *line) {
    // Skip comments and empty lines
    char *trimmed = trim_whitespace(line);
    if (trimmed[0] == '#' || trimmed[0] == '\0') {
        return;
    }

    // Find the '=' separator
    char *equals = strchr(trimmed, '=');
    if (!equals) {
        return;  // Invalid line, skip silently
    }

    // Split into key and value
    *equals = '\0';
    char *key = trim_whitespace(trimmed);
    char *value = trim_whitespace(equals + 1);

    // Parse configuration keys
    if (strcmp(key, "default_key_name") == 0) {
        if (g_config.default_key_name) {
            free(g_config.default_key_name);
        }
        g_config.default_key_name = strdup(value);
    }
    else if (strcmp(key, "default_algorithm") == 0) {
        if (strcmp(value, "dilithium") == 0) {
            g_config.default_algorithm = strdup(value);
        } else {
            fprintf(stderr, "Warning: Unknown algorithm '%s' in config (only 'dilithium' supported)\n", value);
        }
    }
    else if (strcmp(key, "armor") == 0) {
        g_config.armor_enabled = parse_bool(value);
    }
    else if (strcmp(key, "keyring_dir") == 0) {
        if (g_config.keyring_dir) {
            free(g_config.keyring_dir);
        }
        g_config.keyring_dir = strdup(value);
    }
}

// Load configuration from ~/.qgp/config
int qgp_config_load(void) {
    char *home = get_home_dir();
    if (!home) {
        return -1;  // Can't find home directory
    }

    char *config_dir = build_path(home, DEFAULT_KEYRING_DIR);
    char *config_path = build_path(config_dir, "config");
    free(config_dir);

    // If config file doesn't exist, use defaults (not an error)
    if (!file_exists(config_path)) {
        free(config_path);
        return 0;
    }

    FILE *fp = fopen(config_path, "r");
    if (!fp) {
        free(config_path);
        return -1;
    }

    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), fp)) {
        parse_config_line(line);
    }

    fclose(fp);
    free(config_path);
    return 0;
}

// Get the global configuration
const qgp_config_t* qgp_config_get(void) {
    return &g_config;
}

// Free configuration resources
void qgp_config_free(void) {
    if (g_config.default_key_name) {
        free(g_config.default_key_name);
        g_config.default_key_name = NULL;
    }
    if (g_config.keyring_dir) {
        free(g_config.keyring_dir);
        g_config.keyring_dir = NULL;
    }
}

// Create a default configuration file with comments
int qgp_config_create_default(void) {
    char *home = get_home_dir();
    if (!home) {
        fprintf(stderr, "Error: Cannot determine home directory\n");
        return -1;
    }

    char *config_dir = build_path(home, DEFAULT_KEYRING_DIR);
    char *config_path = build_path(config_dir, "config");
    free(config_dir);

    // Check if config already exists
    if (file_exists(config_path)) {
        fprintf(stderr, "Configuration file already exists: %s\n", config_path);
        free(config_path);
        return -1;
    }

    FILE *fp = fopen(config_path, "w");
    if (!fp) {
        fprintf(stderr, "Error: Cannot create configuration file: %s\n", config_path);
        free(config_path);
        return -1;
    }

    // Write default configuration with helpful comments
    fprintf(fp, "# QGP Configuration File\n");
    fprintf(fp, "# This file contains default settings for QGP operations\n");
    fprintf(fp, "# Lines starting with # are comments\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# Default identity for signing and decryption operations\n");
    fprintf(fp, "# If specified, you don't need to use --key flag\n");
    fprintf(fp, "# default_key_name = alice\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# Default signature algorithm (only dilithium is currently supported)\n");
    fprintf(fp, "default_algorithm = dilithium\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# ASCII armor preference (yes or no)\n");
    fprintf(fp, "# When enabled, signatures are saved in .asc format (human-readable)\n");
    fprintf(fp, "armor = yes\n");
    fprintf(fp, "#\n");
    fprintf(fp, "# Custom keyring directory (default: ~/.qgp)\n");
    fprintf(fp, "# keyring_dir = /custom/path\n");
    fprintf(fp, "#\n");

    fclose(fp);
    printf("Created default configuration file: %s\n", config_path);
    printf("Edit this file to customize default settings.\n");
    free(config_path);
    return 0;
}
