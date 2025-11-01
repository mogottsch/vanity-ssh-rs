# vanity-ssh-rs

Generate SSH key pairs with custom patterns in the public key.

![screenshot](screenshot.png)

## Install

```bash
cargo install vanity-ssh-rs
```

## Usage

```bash
vanity-ssh-rs <pattern1> [<pattern2> ...] [-t <threads>] [--ntfy <topic>]
```

**Patterns:**

- Plain text: matches suffix (e.g., `yee` matches keys ending with "yee")
- `/regex/`: matches regex pattern (e.g., `/(?i)hello/` for case-insensitive "hello")
- Multiple patterns: any match will be accepted

**Options:**

- `-t <threads>`: Number of threads (defaults to CPU count)
- `--ntfy <topic>`: Send notification to [ntfy.sh](https://ntfy.sh) topic when found

## Examples

```bash
# Find a key ending with "yee"
vanity-ssh-rs yee

# Match any of several patterns
vanity-ssh-rs yee woo "/(?i)hello/"

# With notification when found
vanity-ssh-rs yee --ntfy mytopic

# Use more threads for faster generation
vanity-ssh-rs yee -t 8
```

Generated keys are saved to the `out/` directory.

## Benchmarking

Run benchmarks to measure key generation performance:

```bash
cargo bench --bench key_generation
```

