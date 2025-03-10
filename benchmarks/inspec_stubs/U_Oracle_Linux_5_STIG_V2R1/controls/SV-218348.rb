control 'SV-218348' do
  title 'There must be no .rhosts, .shosts, hosts.equiv, or shosts.equiv files on the system.'
  desc 'The .rhosts, .shosts, hosts.equiv, and shosts.equiv files are used to configure host-based authentication for individual users or the system.  Host-based authentication is not sufficient for preventing unauthorized access to the system.'
  desc 'check', 'Check for the existence of the files.

# find / -name .rhosts
# find / -name .shosts
# find / -name hosts.equiv
# find / -name shosts.equiv

If .rhosts, .shosts, hosts.equiv, or shosts.equiv are found and their use has not been documented and approved by the IAO, this is a finding.'
  desc 'fix', 'Remove all the r-commands access control files.

Procedure:
# find / -name .rhosts -exec rm {} \\;
# find / -name .shosts -exec rm {} \\;
# find / -name hosts.equiv -exec rm {} \\;
# find / -name shosts.equiv -exec rm {} \\;'
  impact 0.7
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19823r554381_chk'
  tag severity: 'high'
  tag gid: 'V-218348'
  tag rid: 'SV-218348r603259_rule'
  tag stig_id: 'GEN002040'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19821r554382_fix'
  tag 'documentable'
  tag legacy: ['V-11988', 'SV-63621']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
