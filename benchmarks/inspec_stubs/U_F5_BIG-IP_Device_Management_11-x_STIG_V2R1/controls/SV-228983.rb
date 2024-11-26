control 'SV-228983' do
  title 'The BIG-IP appliance must be configured to alert the ISSO and SA (at a minimum) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected. 

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.'
  desc 'check', 'Verify the BIG-IP appliance is configured to alert the ISSO and SA (at a minimum) in the event of an audit processing failure. 

Navigate to the BIG-IP System manager >> System >> Logs >> Configuration >> Options.

Verify "MCP" under the "Audit Logging" section is set to Debug.

If the BIG-IP appliance is not configured to alert in the event of an audit processing failure, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to alert the ISSO and SA (at a minimum) in the event of an audit processing failure.'
  impact 0.3
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31298r517996_chk'
  tag severity: 'low'
  tag gid: 'V-228983'
  tag rid: 'SV-228983r557520_rule'
  tag stig_id: 'F5BI-DM-000067'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31275r517997_fix'
  tag 'documentable'
  tag legacy: ['SV-74553', 'V-60123']
  tag cci: ['CCI-000366', 'CCI-000139']
  tag nist: ['CM-6 b', 'AU-5 a']
end
