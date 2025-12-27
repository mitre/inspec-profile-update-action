control 'SV-215432' do
  title 'There must be no .rhosts, .shosts, hosts.equiv, or shosts.equiv files on the AIX system.'
  desc 'Trust files are convenient, but when used in conjunction with the remote login services, they can allow unauthenticated access to a system.'
  desc 'check', 'Check for the existence of the files using: 
# find / -name .rhosts 
# find / -name .shosts 
# find / -name hosts.equiv 
# find / -name shosts.equiv 

If ".rhosts", ".shosts", "hosts.equiv", or "shosts.equiv" are found, this is a finding.'
  desc 'fix', 'Remove the ".rhosts", ".shosts", "hosts.equiv", and/or "shosts.equiv" files.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16630r294747_chk'
  tag severity: 'medium'
  tag gid: 'V-215432'
  tag rid: 'SV-215432r508663_rule'
  tag stig_id: 'AIX7-00-003138'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-16628r294748_fix'
  tag 'documentable'
  tag legacy: ['SV-101837', 'V-91739']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
