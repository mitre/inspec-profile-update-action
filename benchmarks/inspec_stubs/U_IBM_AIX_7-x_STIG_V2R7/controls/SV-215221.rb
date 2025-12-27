control 'SV-215221' do
  title 'AIX root passwords must never be passed over a network in clear text form.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc 'check', 'Determine if root has logged in over an unencrypted network connection: 

# last | grep "root " | egrep -v "reboot|console" | more 
root      pts/1        10.74.17.76           Jul 4 16:44 - 17:39  (00:54)

Next, determine if the SSH daemon is running: 

# ps -ef |grep sshd 
root  3670408  6029762   0   Jan 24      -  0:00 /usr/sbin/sshd

If root has logged in over the network and SSHD is not running, this is a finding.'
  desc 'fix', 'If OpenSSH server is not installed, install it from the from AIX DVD Volume 1 using the following command (assuming that the DVD device is /dev/cd0):
# installp -aXYgd /dev/cd0 -e /tmp/install.log openssh.base.server

Start SSH server if it is not started:
# startsrc -s sshd

Enable SSH on the system and use it for all remote connections used to attain root access. 

Disable direct root remote login:
# chsec -f /etc/security/user -s root -a rlogin=false'
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16419r294114_chk'
  tag severity: 'high'
  tag gid: 'V-215221'
  tag rid: 'SV-215221r877396_rule'
  tag stig_id: 'AIX7-00-001124'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-16417r294115_fix'
  tag 'documentable'
  tag legacy: ['V-91293', 'SV-101391']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
