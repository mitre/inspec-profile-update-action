control 'SV-256092' do
  title 'The Riverbed NetProfiler must be configured to use redundant Syslog servers that are configured on a different system than the NetProfiler appliance.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Go to Administration >> General Settings. 

Under "Syslog", verify the entries for Server 1 Host and Server 2 Host are configured. 

Verify "Audit Trail" and "Events" are selected for each Syslog server. 

If this is not true, this is a finding.'
  desc 'fix', 'Go to Administration >> General Settings. 

Configure the entry for Server 1 Host. 

Configure the entry for Server 2 Host. 

Check "Audit Trail" and "Events" for each configured server.'
  impact 0.5
  ref 'DPMS Target Riverbed NetProfiler'
  tag check_id: 'C-59766r882782_chk'
  tag severity: 'medium'
  tag gid: 'V-256092'
  tag rid: 'SV-256092r882784_rule'
  tag stig_id: 'RINP-DM-000057'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-59709r882783_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
