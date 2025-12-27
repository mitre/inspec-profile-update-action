control 'SV-45167' do
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
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42511r1_chk'
  tag severity: 'high'
  tag gid: 'V-11988'
  tag rid: 'SV-45167r1_rule'
  tag stig_id: 'GEN002040'
  tag gtitle: 'GEN002040'
  tag fix_id: 'F-38564r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
