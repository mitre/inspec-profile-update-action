control 'SV-204833' do
  title 'The application server must, at a minimum, transfer the logs of interconnected systems in real time, and transfer the logs of standalone systems weekly.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.  Protecting log data is important during a forensic investigation to ensure investigators can track and understand what may have occurred.  Off-loading should be set up as a scheduled task but can be configured to be run manually, if other processes during the off-loading are manual.

Off-loading is a common process in information systems with limited log storage capacity.'
  desc 'check', 'Verify the log records are being off-loaded, at a minimum of real time for interconnected systems and weekly for standalone systems.

If the application server is not meeting these requirements, this is a finding.'
  desc 'fix', 'Configure the application server to off-load interconnected systems in real time and standalone systems weekly.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4953r283140_chk'
  tag severity: 'medium'
  tag gid: 'V-204833'
  tag rid: 'SV-204833r508029_rule'
  tag stig_id: 'SRG-APP-000515-AS-000203'
  tag gtitle: 'SRG-APP-000515'
  tag fix_id: 'F-4953r283141_fix'
  tag 'documentable'
  tag legacy: ['SV-71697', 'V-57425']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
