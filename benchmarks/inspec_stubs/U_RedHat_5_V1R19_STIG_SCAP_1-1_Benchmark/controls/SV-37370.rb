control 'SV-37370' do
  title 'There must be no .rhosts, .shosts, hosts.equiv, or shosts.equiv files on the system.'
  desc 'The .rhosts, .shosts, hosts.equiv, and shosts.equiv files are used to configure host-based authentication for individual users or the system.  Host-based authentication is not sufficient for preventing unauthorized access to the system.'
  desc 'fix', 'Remove all the r-commands access control files.

Procedure:
# find / -name .rhosts -exec rm {} \\;
# find / -name .shosts -exec rm {} \\;
# find / -name hosts.equiv -exec rm {} \\;
# find / -name shosts.equiv -exec rm {} \\;'
  impact 0.7
  ref 'DPMS Target Red Hat 5'
  tag severity: 'high'
  tag gid: 'V-11988'
  tag rid: 'SV-37370r1_rule'
  tag stig_id: 'GEN002040'
  tag gtitle: 'GEN002040'
  tag fix_id: 'F-31301r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
