control 'SV-215435' do
  title 'All AIX interactive users must be assigned a home directory in the passwd file and the directory must exist.'
  desc 'All users must be assigned a home directory in the passwd file. Failure to have a home directory may result in the user being put in the root directory. This could create a Denial of Service because the user would not be able to perform useful tasks in this location.'
  desc 'check', 'Verify each interactive user is assigned a home directory:

# cut -d: -f1,6 /etc/passwd
root
srvproxy
doejohn

If an interactive user is not assigned a home directory, this is a finding.

Verify that the interactive user home directories exist on the system:

# cut -d: -f6 /etc/passwd | xargs -n1 ls -ld

drwxr-xr-x    2 doejohn  staff           256 Jan 25 13:18 /home/doejohn

drwxr-xr-x    2 sshd     system          256 Aug 11 2017  /home/srvproxy

drwx------    2 root     system          256 Jan 30 12:54 /root

If any interactive user home directory does not exist, this is a finding.'
  desc 'fix', 'Remove any unauthorized accounts with no home directory. 

If the account is valid, create the home directory using the appropriate system administration utility or process.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16633r294756_chk'
  tag severity: 'medium'
  tag gid: 'V-215435'
  tag rid: 'SV-215435r508663_rule'
  tag stig_id: 'AIX7-00-003141'
  tag gtitle: 'SRG-OS-000480-GPOS-00230'
  tag fix_id: 'F-16631r294757_fix'
  tag 'documentable'
  tag legacy: ['V-91755', 'SV-101853']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
