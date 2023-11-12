#!/bin/bash

function _install_pip_requirements() {
    file="requirements.txt"
    python3 -m venv venv
    source venv/bin/activate
    python3 -m pip --disable-pip-version-check install --upgrade pip
    python3 -m pip install wheel==0.36.2
    python3 -m pip install -r $file
    deactivate
}