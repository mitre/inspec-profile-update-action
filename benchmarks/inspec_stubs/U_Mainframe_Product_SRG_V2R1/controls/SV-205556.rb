control 'SV-205556' do
  title 'The Mainframe Product must provide an immediate real-time alert to the operations staff, system programmers, and/or security administrators, at a minimum, of all audit failure events requiring real-time alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'If the Mainframe Product does not perform audit data management or storage function, this is not applicable.

Examine configuration settings.

If the Mainframe Product does not provide for immediate real-time alerts to operations staff, system programmers, and/or security administrators for audit failures requiring real-time alerts, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to provide for immediate real-time alerts to operations staff, system programmers, and/or security administrators for audit failures requiring real-time alerts.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5822r299895_chk'
  tag severity: 'medium'
  tag gid: 'V-205556'
  tag rid: 'SV-205556r851320_rule'
  tag stig_id: 'SRG-APP-000360-MFP-000152'
  tag gtitle: 'SRG-APP-000360'
  tag fix_id: 'F-5822r299896_fix'
  tag 'documentable'
  tag legacy: ['SV-82753', 'V-68263']
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
