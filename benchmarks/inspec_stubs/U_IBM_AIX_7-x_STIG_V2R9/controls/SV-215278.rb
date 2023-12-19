control 'SV-215278' do
  title 'All files and directories contained in users home directories on AIX must be group-owned by a group in which the home directory owner is a member.'
  desc 'If the Group Identifier (GID) of the home directory is not the same as the GID of the user, this would allow unauthorized access to files.'
  desc 'check', "Check the contents of user home directories for files group-owned by a group of which the home directory's owner is not a member. 

List the user accounts: 

# cut -d : -f 1 /etc/passwd 
root
daemon
bin
sys
adm
uucp
nobody
invscout
snapp
ipsec
srvproxy
esaadmin
sshd
doejohn
dirtjoe

For each user account, get a list of group names for files in the user's home directory: 

# find < users home directory > -exec ls -lLd {} \\;

Obtain the list of group names associated with the user's account:

# lsuser -a groups < user name > 
doejohn groups=staff

Check the group name lists:

# cat /etc/group
system:!:0:root,srvproxy,esaadmin
staff:!:1:ipsec,srvproxy,esaadmin,sshd,doejohn
bin:!:2:root,bin
sys:!:3:root,bin,sys
adm:!:4:bin,adm
mail:!:6:
security:!:7:root
cron:!:8:root
audit:!:10:root
ecs:!:28:
nobody:!:4294967294:nobody,lpd
usr:!:100:dirtjoe
perf:!:20:
shutdown:!:21:
invscout:!:12:invscout
snapp:!:13:snapp
ipsec:!:200:
sshd:!:201:sshd

If there are group names in the file list not present in the user list, this is a finding."
  desc 'fix', "Change the group of a file not group-owned by a group where the home directory's owner is a member using command: 
# chgrp [user's primary group] [file with bad group ownership]"
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16476r294285_chk'
  tag severity: 'medium'
  tag gid: 'V-215278'
  tag rid: 'SV-215278r508663_rule'
  tag stig_id: 'AIX7-00-002087'
  tag gtitle: 'SRG-OS-000480-GPOS-00230'
  tag fix_id: 'F-16474r294286_fix'
  tag 'documentable'
  tag legacy: ['SV-101867', 'V-91769']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
