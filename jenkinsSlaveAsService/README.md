# Setup a jenkins headless slave with a service account

## Installation of operating system

Install a headless windows 2019 server.

## Setup open ssh

Use remote desktop to connect to the computer.

Start from cmd and start powershell
Check for the latest openssh verion.

``` Powershell
  Get-WindowsCapability -Online | ? Name -like 'OpenSSH*'

  # This should return the following output:

  Name  : OpenSSH.Client~~~~0.0.1.0
  State : Installed
  Name  : OpenSSH.Server~~~~0.0.1.0
  State : NotPresent

  # Install the OpenSSH Server
  Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

  # Should return the following output:

  Path          :
  Online        : True
  RestartNeeded : False
```

Once installed the service needs to be started automatically on reboot

``` Powershell
  Start-Service sshd
  # OPTIONAL but recommended:
  Set-Service -Name sshd -StartupType 'Automatic'
  # Confirm the Firewall rule is configured. It should be created automatically by setup.
  Get-NetFirewallRule -Name *ssh*
  # There should be a firewall rule named "OpenSSH-Server-In-TCP", which should be enabled
```

Verify the installation by trying to ssh the computer from git bash or terminal on mac

``` bash
  ssh Administrator@hostname
  $ ssh administrator@HOSTNAME.DOMAIN
  # answer yes to the authenticity question
  # start powershell manually
  powershell
```

Now you don't need to be connected to the computer using remote desktop.

Set the default shell to powershell

``` powershell
    New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
```

## Next steps assumes you are connected using ssh and in powershell

As the title says, you need to be connected to the computer using ssh, once connected make sure you are running the commands in powershell, indicated by PS to the left of the command prompt.

### install chocolatey

``` powershell
  Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
```

### install rest of dependendecies using choco

``` powershell
    choco install dotnetcore-sdk -f -A -y
    choco install dotnet4.7.2   -f -A -y
    choco install git -f -A -y
    choco install jdk8 -f -A -y
    choco install vscode -f -A -y
    choco install 7zip -f -A -y
    choco install python -f -A -y
```

### Create an user for jenkins

``` Powershell
  $Password = Read-Host -AsSecureString
  # Type in a password
  New-LocalUser "jenkins" -Password $Password -FullName "Jenkins Robot User" -Description "This is a robot users used for robot tasks"
  Set-LocalUser -Name "jenkins" -PasswordNeverExpires 1
```

### create jenkins workspace folder

I use c:\jw for jenkins workspace

``` Powershell
  mkdir c:\jw
  $path = 'C:\jw'
  $acl = Get-Acl -Path $path
  $accessrule = New-Object System.Security.AccessControl.FileSystemAccessRule ('jenkins', 'FullControl', 'ContainerInherit, ObjectInherit', 'InheritOnly', 'Allow')
  $acl.SetAccessRule($accessrule)
  Set-Acl -Path $path -AclObject $acl
```

### Now create the Jenkins slave

Copy jenkinsslave.xml to the server, then ssh to the computer
Ssh to the computer using the jenkins account

``` bash
  scp ./dependencies/jenkinsslave.xml jenkins@HOSTNAME.DOMAIN:jenkinsslave.xml
  ssh jenkins@HOSTNAME.DOMAIN
```

### download jenkins slave dependencies

``` Powershell
    mkdir slave
    copy-item jenkinsslave.xml ./slave/
    cd slave
    iwr -uri http://JENKINS_URL/jnlpJars/agent.jar -OutFile agent.jar
    Invoke-WebRequest -uri https://github.com/kohsuke/winsw/releases/download/winsw-v2.2.0/WinSW.NET4.exe  -OutFile jenkinsslave.exe
    (Get-Content .\jenkinsslave.xml).replace('%COMPUTERNAME%', $ENV:COMPUTERNAME) | Set-Content .\jenkinsslave.xml
```

Logout using exit
Sign in as administrator again and then install the service

``` bash
  ssh administrator@HOSTNAME.DOMAIN.schantz.com
```

``` powershell
  cd C:\Users\jenkins\slave\
  .\jenkinsslave.exe install /p

  # Use computername before username
  Username: HOSTNAME\jenkins
  Password: ********

  .\jenkinsslave.exe start
  Set-Service -Name jenkinsslave -StartupType 'Automatic'
```

## From jenkins UI create a jenkins node with the name of the computer

Once you have created a jenkins node / slave from the UI you can restart the slave and it will connect.
Make sure to the workspace to c:\jw

```
Restart-Computer -Force
```