control 'SV-12489' do
  title 'There must be no .rhosts, .shosts, hosts.equiv, or shosts.equiv files on the system.'
  desc 'The .rhosts, .shosts, hosts.equiv, and shosts.equiv files are used to configure host-based authentication for individual users or the system.  Host-based authentication is not sufficient for preventing unauthorized access to the system.'
  desc 'check', 'Check for the existence of the files.

# find / -name .rhosts
# find / -name .shosts
# find / -name hosts.equiv
# find / -name shosts.equiv

If .rhosts, .shosts, hosts.equiv, or shosts.equiv are found, this is a finding.'
  desc 'fix', 'Remove the .rhosts, .shosts, hosts.equiv, and/or shosts.equiv files.'
  impact 0.7
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-7953r2_chk'
  tag severity: 'high'
  tag gid: 'V-11988'
  tag rid: 'SV-12489r2_rule'
  tag stig_id: 'GEN002040'
  tag gtitle: 'GEN002040'
  tag fix_id: 'F-11249r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
