# Alert hooks

The oomph logger on Linux has no network and runs nothing. When an incident opens, when something is
killed in it, and when it closes, it writes a record into `/var/log/oomph/alerts`; `oomph-alert.service`
then runs every script in `/etc/oomph/alert.d/` with that record.

    sudo install -m 755 -o root 10-ntfy /etc/oomph/alert.d/10-ntfy
    sudoedit /etc/oomph/alert.secret           # add the line NTFY_URL=https://ntfy.sh/your-topic
    sudo systemctl enable --now oomph-alert.path
    sudo oomph alert --test

A script runs only if it is root's, writable by root only and readable and executable by everyone (and so
is the folder), at most 30 s per record, as a throwaway account that may reach the network (a script only
root may read would fail at every alert; `oomph doctor` and `oomph alert --test` name one). Every account
can read the scripts, so **no secret goes into one**: a topic, a webhook's URL or a password goes into
`/etc/oomph/alert.secret` (root's, mode 0600, one `KEY=value` per line; the installer makes it empty; edit it
with `sudoedit`, never with `echo … >>`, which puts the secret on a command line and makes a missing file
readable by all),
which `oomph-alert.service` hands to the hooks as `$CREDENTIALS_DIRECTORY/alert`. The examples read their
line from it and pass it to curl in a config on fd 3, never on the command line, which other accounts can
read in `/proc`. `sudo oomph alert --test` runs the hooks the way the unit does, as a throwaway account with
that file, so a hook that passes the test works at a real alert. It gets these variables, each cut to
200 characters of `A-Z a-z 0-9 space . , : ; ( ) / % + @ _ -` (anything else becomes `?`):

| Variable | Value |
|---|---|
| `OOMPH_EVENT` | `open`, `kill`, `close` (`test` from `oomph alert --test`) |
| `OOMPH_INCIDENT` | the incident's id, e.g. `20261120-030940` |
| `OOMPH_LEVEL` | `critical` (open, kill) or `notice` (close) |
| `OOMPH_HOST`, `OOMPH_TITLE`, `OOMPH_MESSAGE` | the machine, a title, the headline ("OOM killer killed node (pid 48211, 2.1 GB)") |
| `OOMPH_REPORT` | the report's path on this machine (at `close`) |

The same record arrives as JSON on stdin, unshortened. Process names and purposes in it are text any local
user chooses. **Never `eval` a variable, quote every expansion**, and never pass one to a shell. Where the
text lands in markup, escape it as that service asks: Slack reads `<!channel>` and `<http://x|y>` in a message,
so `20-slack-webhook` turns `& < >` into `&amp; &lt; &gt;` (the `OOMPH_*` variables cannot hold them).

Quiet incidents (containers at their own memory limit) and the continuation of a long incident run no hook.
