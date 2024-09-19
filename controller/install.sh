#!/bin/bash
# This script is used to install the Avere vFXT controller software on an Azure VM
# It is intended to be used with Azure Image Builder
set -ex
export DEBIAN_FRONTEND=noninteractive

AZCLI_VERSION=2.63.0
TERRAFORM_VERSION=1.9.4
AVERE_TERRAFORM_PROVIDER_VERSION=1.3.3

echo "Sleeping for 2 minutes to allow the VM to settle"
sleep 120


echo "Installing Pre-requisites"
apt-get update
apt-get install -y      \
    apt-transport-https \
    build-essential     \
    ca-certificates     \
    curl                \
    dirmngr             \
    gnupg               \
    jq                  \
    libssl-dev          \
    lsb-release         \
    nfs-common          \
    python-dev-is-python3 \
    python3             \
    python3-dev         \
    python3-pip         \
    python-setuptools   \
    sshpass             \
    unzip


echo "Installing the Azure CLI"
mkdir -p /etc/apt/keyrings
curl -sLS https://packages.microsoft.com/keys/microsoft.asc |
  gpg --dearmor | tee /etc/apt/keyrings/microsoft.gpg > /dev/null
chmod go+r /etc/apt/keyrings/microsoft.gpg

AZ_DIST=$(lsb_release -cs)
echo "Types: deb
URIs: https://packages.microsoft.com/repos/azure-cli/
Suites: ${AZ_DIST}
Components: main
Architectures: $(dpkg --print-architecture)
Signed-by: /etc/apt/keyrings/microsoft.gpg" | tee /etc/apt/sources.list.d/azure-cli.sources

apt-get update
apt-get install -y azure-cli
apt upgrade -y
apt autoremove -y

echo "Installing the Avere SDK"
python3 -m pip install --upgrade pip pyOpenSSL requests urllib3 azure-cli==${AZCLI_VERSION}
python3 -m pip install git+https://github.com/Azure/AvereSDK.git@main

echo "Enabling unattended upgrades"
cp /usr/share/unattended-upgrades/20auto-upgrades /etc/apt/apt.conf.d/20auto-upgrades


echo "Retrieving and installing terraform"
curl -L -o /tmp/terraform.zip https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip
unzip /tmp/terraform.zip terraform -d /usr/local/bin
chmod 755 /usr/local/bin/terraform
rm /tmp/terraform.zip

echo "Retrieving and installing the Avere Terraform provider"
curl -L -o /usr/local/bin/terraform-provider-avere https://github.com/Azure/Avere/releases/download/v${AVERE_TERRAFORM_PROVIDER_VERSION}/terraform-provider-avere
chmod 755 /usr/local/bin/terraform-provider-avere

echo "Cleaning up the build tools"
apt remove --purge -y                                     \
    g++ gcc build-essential binutils dpkg-dev \
    python2.7-dev python-dev cpp binutils-common    \
    binutils-x86-64-linux-gnu     \
    linux-libc-dev manpages-dev
apt clean
rm -rf /usr/src/linux*headers*


echo "Update alternatives"
update-alternatives --install /usr/bin/python python /usr/bin/python3 10


mkdir -p /examples
REPO=Azure/AvereSDK
BRANCH=main
curl -L -o /examples/add-nodes https://raw.githubusercontent.com/${REPO}/${BRANCH}/controller/examples/add-nodes
curl -L -o /examples/avere-cluster.json https://raw.githubusercontent.com/${REPO}/${BRANCH}/controller/examples/avere-cluster.json
curl -L -o /examples/create-cloudbacked-cluster https://raw.githubusercontent.com/${REPO}/${BRANCH}/controller/examples/create-cloudbacked-cluster
curl -L -o /examples/create-minimal-cluster https://raw.githubusercontent.com/${REPO}/${BRANCH}/controller/examples/create-minimal-cluster
curl -L -o /examples/destroy-cluster https://raw.githubusercontent.com/${REPO}/${BRANCH}/controller/examples/destroy-cluster
curl -L -o /examples/VFXT_README https://raw.githubusercontent.com/${REPO}/${BRANCH}/controller/examples/VFXT_README
printf "\nCheck out /examples/VFXT_README for help on using this Avere Controller virtual machine\n\n" > /etc/update-motd.d/99-vfxt
