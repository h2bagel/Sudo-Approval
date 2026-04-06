# sudo-approval

**sudo-approval** is a fork of the original `sudo_confirm` plugin.\
It is a sudo approval plugin that prompts users to confirm sudo commands before execution, with added features.

## Features

- Prompts users before executing commands as another user or root
- ANSI escape sequence neutralization in command output
- Redacts sensitive command-line arguments (`pass=` and `-p`)
- Colored output for root user prompts
- Logging to `/var/log/sudo_approval.log`

## License

- Original code: MIT License (© 2024 e792a8)
- Modifications: LGPL v3 (© 2026 h2bagel)

This project **combines MIT-licensed code with LGPL-licensed modifications**. See the `LICENSE` file for full license texts.

## Installation

### From Source

```bash
cd Sudo-Approval
sudo ./install-script
```

## Removal

### From Source

```bash
sudo sed -i '/^Plugin\s\+sudo_approval\s\+\/usr\/lib\/sudo\/sudo_approval.so.*/d' etc/sudo.conf
sudo rm /usr/lib/sudo/sudo_confirm.so
```

## Options

| Option      | Description                                   |
| ----------- | --------------------------------------------- |
| `yes`       | Defaults prompt to `[Y/n]` instead of `[y/N]` |
| `noconfirm` | Bypasses confirmation prompt entirely         |

At runtime, the plugin will prompt:

```text
Do you want to run '<command>' as <user>?
[y/N]
```

- If `yes` is specified, it defaults to `[Y/n]`.
- If `noconfirm` is specified, the prompt is skipped.

## Logging

All suspicious activity is logged to:

```text
/var/log/sudo_approval.log
```

This includes:

- Truncated or empty commands
- Sensitive environment variables
- ANSI escape sequences in input

## Contributing

- Fork the repository
- Make modifications
- Submit pull requests

Ensure **all modifications comply with LGPL v3**, and retain MIT licensing notices for original code.

## Notes

- Requires a controlling terminal (`/dev/tty`) for interactive prompts
- ANSI sequences and sensitive arguments are sanitized before display
- Compatible with `sudo >= 1.9` approval plugin API



