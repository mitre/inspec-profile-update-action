control 'SV-250649' do
  title 'There must be no .rhosts  or hosts.equiv files on the system.'
  desc 'The .rhosts or hosts.equiv files are used to configure host-based authentication for individual users or the system. Host-based authentication is not sufficient for preventing unauthorized access to the system.'
  desc 'check', "The files hosts.equiv (/etc) and .rhosts (in the user home directory) contains host/user pairs to be trusted by the local system.  

Locate the files:
# ls -l /etc/hosts.equiv
# find / | grep .rhosts
or
# cd <user's home directory> 
# ls -l .rhosts

If the hosts.equiv file or one or more .rhosts files are found, this is a finding."
  desc 'fix', "Remove the file(s):
# rm -f /etc/hosts.equiv
# rm -f <user's home directory>/.rhosts"
  impact 0.7
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54084r798944_chk'
  tag severity: 'high'
  tag gid: 'V-250649'
  tag rid: 'SV-250649r798946_rule'
  tag stig_id: 'SRG-OS-000248-ESXI5'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54038r798945_fix'
  tag 'documentable'
  tag legacy: ['V-39252', 'SV-51068']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
