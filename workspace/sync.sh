#!/usr/bin/env bash

# Sync local directory (usually containing code) to kali remote directory
# which is mounted using sshfs on dir "remote" (execute mount.sh first)
# Enables having code in this repo and running it on kali (without copying, push/pull, etc.)

LOCAL_DIR=$1
# SSHFS_DIR=$2
# REMOTE_HOST="user@remote_host"

while inotifywait -r -e modify,create,delete,move "$LOCAL_DIR"; do
    rsync -avz --delete "$LOCAL_DIR" "remote/$LOCAL_DIR"
done