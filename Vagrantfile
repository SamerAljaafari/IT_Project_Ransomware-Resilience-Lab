# -*- mode: ruby -*-
# vi: set ft=ruby :
#
# Ransomware-resilience lab — three-VM isolated environment:
#   * fileserver : Windows Server 2019 Standard (WinRM), hosts the SMB dataset
#   * attacker   : Kali Linux, drives the attack over the private network
#   * vhr        : Ubuntu 22.04, Veeam Hardened Repository (immutable backups)
#
# Network model (per VM):
#   nic1 = NAT        -> Vagrant management + internet. Disconnect to "seal"
#                        the lab (isolated testing), reconnect to install tools.
#   nic2 = host-only  -> isolated 192.168.56.0/24 lab link. VM<->VM only.
#
# Fixed IPs:  fileserver 192.168.56.10 | attacker 192.168.56.20 | vhr 192.168.56.30
#
# The Ubuntu VHR is auto-provisioned on "vagrant up" (repo user + directory).
# The Windows and Kali boxes are brought up from their base images; installing
# the tested solutions, loading the dataset and the SMB share are separate,
# documented steps (see report section 2.1).

Vagrant.configure("2") do |config|

  
  # ======== VM 1 — Windows Server 2019 file server ========
 
  config.vm.define "fileserver" do |fileserver|
    fileserver.vm.box = "gusztavvargadr/windows-server-2019-standard"
    # Fallback:  "peru/windows-server-2019-standard-x64-eval"

    fileserver.vm.communicator = "winrm"
    fileserver.winrm.username   = "vagrant"
    fileserver.winrm.password   = "vagrant"
    fileserver.winrm.transport  = :negotiate
    fileserver.vm.boot_timeout  = 600
    fileserver.winrm.timeout    = 600
    fileserver.winrm.retry_limit = 100
    fileserver.winrm.retry_delay = 10

    # nic2: isolated lab link, fixed IP (nic1 NAT is added by Vagrant).
    fileserver.vm.network "private_network", ip: "192.168.56.10"

    fileserver.vm.provider "virtualbox" do |vb|
      vb.gui    = true
      vb.memory = 4096
      vb.cpus   = 2
      vb.name   = "ransomlab-fileserver-2019"
      vb.customize ["modifyvm", :id, "--vram", "64"]
    end
  end
  # ======== VM 2 — Kali Linux attacker ========
 
  config.vm.define "attacker" do |attacker|
    attacker.vm.box = "kalilinux/rolling"
    attacker.vm.hostname = "kali-attacker"
    # Kali uses SSH (Vagrant default) — no communicator override needed.

    # nic2: same isolated lab link, fixed IP.
    attacker.vm.network "private_network", ip: "192.168.56.20"

    attacker.vm.provider "virtualbox" do |vb|
      vb.gui    = true
      vb.memory = 3072
      vb.cpus   = 2
      vb.name   = "ransomlab-attacker-kali"
    end
  end
 # ======== VM 3 — Ubuntu 22.04 Veeam Hardened Repository ========
 config.vm.define "vhr" do |vhr|
   vhr.vm.box = "ubuntu/jammy64"
   vhr.vm.hostname = "veeam-hardened-repo"
   vhr.vm.network "private_network", ip: "192.168.56.30"
   vhr.vm.provider "virtualbox" do |vb|
     vb.gui    = true
     vb.memory = 2048
     vb.cpus   = 2
     vb.name   = "ransomlab-vhr-ubuntu"
   end
   vhr.vm.provision "shell", inline: <<-SHELL
     apt-get update -qq
     apt-get install -y openssh-server
     useradd -m veeamrepo || true
     echo "veeamrepo:veeamrepo123" | chpasswd
     mkdir -p /mnt/veeam-repo
     chown veeamrepo:veeamrepo /mnt/veeam-repo
     usermod -aG sudo veeamrepo
     echo 'veeamrepo ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/veeamrepo
     chmod 440 /etc/sudoers.d/veeamrepo
     chmod 700 /mnt/veeam-repo
     echo "PasswordAuthentication yes" > /etc/ssh/sshd_config.d/allow-password.conf
     sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config.d/60-cloudimg-settings.conf
     systemctl enable ssh
     systemctl restart ssh
   SHELL
 end
end
