control 'SV-215277' do
  title 'All AIX interactive users home directories must be group-owned by the home directory owner primary group.'
  desc 'If the Group Identifier (GID) of the home directory is not the same as the GID of the user, this would allow unauthorized access to files.'
  desc 'check', %q(Check the group ownership for each user in the "/etc/passwd" file using command: 

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

If any user's home directory is not group-owned by the assigned user's primary group, this is a finding. 

Home directories for application accounts requiring different group ownership must be documented using site-defined procedures.)
  desc 'fix', 'Change the group owner for users home directories to the primary group of the assigned user: 
# chgrp <groupname> <directoryname> 

(Replace examples with appropriate group and home directory.) 

Document all changes.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16475r294282_chk'
  tag severity: 'medium'
  tag gid: 'V-215277'
  tag rid: 'SV-215277r508663_rule'
  tag stig_id: 'AIX7-00-002086'
  tag gtitle: 'SRG-OS-000480-GPOS-00230'
  tag fix_id: 'F-16473r294283_fix'
  tag 'documentable'
  tag legacy: ['SV-101861', 'V-91763']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
