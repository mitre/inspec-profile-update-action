control 'SV-38249' do
  title 'There must be no .rhosts, .shosts, hosts.equiv, or shosts.equiv files on the system.'
  desc 'The .rhosts, .shosts, hosts.equiv, and shosts.equiv files are used to configure host-based authentication for individual users or the system.  Host-based authentication is not sufficient for preventing unauthorized access to the system.'
  desc 'fix', 'Remove the .rhosts, .shosts, hosts.equiv, and/or shosts.equiv files.'
  impact 0.7
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'high'
  tag gid: 'V-11988'
  tag rid: 'SV-38249r1_rule'
  tag stig_id: 'GEN002040'
  tag gtitle: 'GEN002040'
  tag fix_id: 'F-31760r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
