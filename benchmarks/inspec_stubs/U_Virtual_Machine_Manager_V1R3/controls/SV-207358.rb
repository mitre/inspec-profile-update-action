control 'SV-207358' do
  title 'The VMM must alert the ISSO and SA (at a minimum) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a VMM is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and VMM operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct VMM component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.'
  desc 'check', 'Verify the VMM alerts the ISSO and SA (at a minimum) in the event of an audit processing failure. If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to alert the ISSO and SA (at a minimum) in the event of an audit processing failure.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7615r365484_chk'
  tag severity: 'medium'
  tag gid: 'V-207358'
  tag rid: 'SV-207358r378634_rule'
  tag stig_id: 'SRG-OS-000046-VMM-000210'
  tag gtitle: 'SRG-OS-000046'
  tag fix_id: 'F-7615r365485_fix'
  tag 'documentable'
  tag legacy: ['SV-71153', 'V-56893']
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
