control 'SV-207455' do
  title 'The VMM must provide an immediate real-time alert to the SA and ISSO, at a minimum, of all audit failure events requiring real-time alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a VMM is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected. 

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'Verify the VMM provides an immediate real-time alert to the SA and ISSO, at a minimum, of all audit failure events requiring real-time alerts.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to provide an immediate real-time alert to the SA and ISSO, at a minimum, of all audit failure events requiring real-time alerts.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7712r365769_chk'
  tag severity: 'medium'
  tag gid: 'V-207455'
  tag rid: 'SV-207455r854626_rule'
  tag stig_id: 'SRG-OS-000344-VMM-001250'
  tag gtitle: 'SRG-OS-000344'
  tag fix_id: 'F-7712r365770_fix'
  tag 'documentable'
  tag legacy: ['V-57111', 'SV-71371']
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
