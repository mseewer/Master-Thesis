#!/usr/bin/env bash

# Sync local directory (usually containing code) to kali remote directory
# which is mounted using sshfs on dir "remote" (execute mount.sh first)
# Enables having code in this repo and running it on kali (without copying, push/pull, etc.)

LOCAL_DIR=$1
# SSHFS_DIR=$2
# REMOTE_HOST="user@remote_host"

# exclude output directory from sync (and deleting on remote)
while inotifywait -r -e modify,create,delete,move --exclude "$LOCAL_DIR/output" "$LOCAL_DIR"; do
    rsync -avz --exclude="$LOCAL_DIR/output" "$LOCAL_DIR" "remote/$LOCAL_DIR"
done