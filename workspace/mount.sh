#!/usr/bin/env bash

# Mount kali remote directory to local directory "remote" using sshfs

loc=$1
# check if loc is one of Zurich, Thun, or Lausanne and set SSH_target variable
if [[ $loc == "Zurich" ]]; then
    SSH_target=kaliZH
    USER=lab
elif [[ $loc == "Thun" ]]; then
    SSH_target=kaliThun
    USER=lab
elif [[ $loc == "Lausanne" ]]; then
    SSH_target=kaliLAU
    USER=kali
else
    echo "Invalid location. Please provide one of Zurich, Thun, or Lausanne."
    exit 1
fi


sshfs ${SSH_target}:/home/${USER}/Documents remote