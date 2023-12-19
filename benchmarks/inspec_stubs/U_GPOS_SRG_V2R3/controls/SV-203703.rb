control 'SV-203703' do
  title 'The operating system must provide an immediate real-time alert to the SA and ISSO, at a minimum, of all audit failure events requiring real-time alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'Verify the operating system provides an immediate real-time alert to the SA and ISSO, at a minimum, of all audit failure events requiring real-time alerts. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to provide an immediate real-time alert to the SA and ISSO, at a minimum, of all audit failure events requiring real-time alerts.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3828r375056_chk'
  tag severity: 'medium'
  tag gid: 'V-203703'
  tag rid: 'SV-203703r379699_rule'
  tag stig_id: 'SRG-OS-000344-GPOS-00135'
  tag gtitle: 'SRG-OS-000344'
  tag fix_id: 'F-3828r375057_fix'
  tag 'documentable'
  tag legacy: ['SV-71511', 'V-57251']
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
