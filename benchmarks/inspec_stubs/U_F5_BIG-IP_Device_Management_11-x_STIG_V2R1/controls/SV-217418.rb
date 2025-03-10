control 'SV-217418' do
  title 'The BIG-IP appliance must be configured to off-load audit records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Verify the BIG-IP appliance is configured to off-load audit records onto a different system or media than the system being audited. 

Navigate to the BIG-IP System manager >> System >> Logs >> Configuration >> Remote Logging.

Verify a syslog destination is configured that off-loads audit records from the BIG-IP appliance that is different from the system being audited.

If BIG-IP appliance is not configured to off-load audit records onto a different system or media, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to off-load audit records onto a different system or media than the system being audited.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18643r290808_chk'
  tag severity: 'medium'
  tag gid: 'V-217418'
  tag rid: 'SV-217418r557520_rule'
  tag stig_id: 'F5BI-DM-000257'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-18641r290809_fix'
  tag 'documentable'
  tag legacy: ['V-60219', 'SV-74649']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
