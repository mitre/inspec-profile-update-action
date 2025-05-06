control 'SV-215331' do
  title 'All AIX users home directories must have mode 0750 or less permissive.'
  desc 'Excessive permissions on home directories allow unauthorized access to user files.'
  desc 'check', %q(Check the home directory mode of each interactive user in "/etc/passwd":

#cut -d : -f 6 /etc/passwd | xargs -n1 ls -ld | more 
drwxr-xr-x   20 root     system         4096 Jan 28 13:46 /
drwxr-xr-x   33 root     system         8192 Jan 28 13:51 /etc
lrwxrwxrwx    1 bin      bin               8 Jan 24 07:23 /bin -> /usr/bin
drwxrwxr-x    4 bin      bin             256 Mar 23 2017  /usr/sys
drwxrwxr-x   15 root     adm            4096 Jan 24 12:26 /var/adm
drwxr-xr-x    2 root     sys            4096 Jan 24 08:43 /usr/lib/uucp
drwxr-xr-x    6 root     system         4096 Jan 24 07:34 /var/adm/invscout
drwxr-xr-x    3 ipsec    ipsec           256 Jan 24 08:43 /etc/ipsec
drwxr-xr-x    2 sshd     system          256 Aug 11 2017  /home/srvproxy
drwxr-xr-x    8 esaadmin system          256 Jan 24 09:02 /var/esa
drwxr-x---    2 doejohn  staff           256 Jan 25 13:18 /home/doejohn

If an interactive user's home directory's mode is more permissive than "0750", this is a finding. 

NOTE: Application directories are allowed and may need "0755" permissions (or greater) for correct operation.)
  desc 'fix', %q(Change the mode of interactive users' home directories to "0750" or less permissive using the following command:
# chmod 0750 <home directory>)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16529r294444_chk'
  tag severity: 'medium'
  tag gid: 'V-215331'
  tag rid: 'SV-215331r508663_rule'
  tag stig_id: 'AIX7-00-003018'
  tag gtitle: 'SRG-OS-000480-GPOS-00230'
  tag fix_id: 'F-16527r294445_fix'
  tag 'documentable'
  tag legacy: ['SV-101857', 'V-91759']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
