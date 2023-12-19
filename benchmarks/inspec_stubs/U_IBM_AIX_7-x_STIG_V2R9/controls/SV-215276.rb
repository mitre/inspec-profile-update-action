control 'SV-215276' do
  title 'All AIX interactive users home directories must be owned by their respective users.'
  desc 'System binaries are executed by privileged users as well as system services, and restrictive permissions are necessary to ensure that their execution of these programs cannot be co-opted.'
  desc 'check', %q(Check the ownership of each user's home directory listed in the "/etc/passwd file": 

# cut -d: -f6 /etc/passwd | xargs ls -lLd

drwxr-xr-x   21 root     system         4096 Jan 29 09:58 /

drwxr-xr-x    4 bin      bin           45056 Jan 24 12:31 /bin

drwxr-xr-x    2 doejohn  staff           256 Jan 25 13:18 /home/doejohn

drwxr-xr-x    2 sshd     system          256 Aug 11 2017  /home/srvproxy

drwx------    2 root     system          256 Jan 30 12:54 /root

drwxrwxr-x    4 bin      bin             256 Mar 23 2017  /usr/sys

drwxrwxr-x   15 root     adm            4096 Jan 24 12:26 /var/adm

drwxr-xr-x    6 root     system         4096 Jan 24 07:34 /var/adm/invscout

drwxr-xr-x    8 esaadmin system          256 Jan 24 09:02 /var/esa


If any user's home directory is not owned by the assigned user, this is a finding.)
  desc 'fix', "Change the owner of a user's home directory to its assigned user using command: 
# chown <user> <home directory>"
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16474r294279_chk'
  tag severity: 'medium'
  tag gid: 'V-215276'
  tag rid: 'SV-215276r508663_rule'
  tag stig_id: 'AIX7-00-002085'
  tag gtitle: 'SRG-OS-000480-GPOS-00230'
  tag fix_id: 'F-16472r294280_fix'
  tag 'documentable'
  tag legacy: ['SV-101859', 'V-91761']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
