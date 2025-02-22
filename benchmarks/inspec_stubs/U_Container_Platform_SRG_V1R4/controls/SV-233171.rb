control 'SV-233171' do
  title 'The container platform must provide an immediate real-time alert to the SA and ISSO, at a minimum, of all audit failure events requiring real-time alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'Review the container platform configuration to determine if it is configured to provide an immediate real-time alert to the SA and ISSO of all audit failure events requiring real-time alerts. 

If the container platform is not configured to provide an immediate real-time alert, this is a finding.'
  desc 'fix', 'Configure the container platform to provide an immediate real-time alert to the SA and ISSO of all audit failure events requiring real-time alerts.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36107r601787_chk'
  tag severity: 'medium'
  tag gid: 'V-233171'
  tag rid: 'SV-233171r879733_rule'
  tag stig_id: 'SRG-APP-000360-CTR-000815'
  tag gtitle: 'SRG-APP-000360'
  tag fix_id: 'F-36075r601001_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
