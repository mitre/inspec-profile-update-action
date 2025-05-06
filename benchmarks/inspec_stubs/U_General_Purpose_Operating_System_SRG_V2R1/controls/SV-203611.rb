control 'SV-203611' do
  title 'The operating system must alert the ISSO and SA (at a minimum) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.'
  desc 'check', 'Verify the operating system alerts the ISSO and SA (at a minimum) in the event of an audit processing failure. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to alert the ISSO and SA (at a minimum) in the event of an audit processing failure.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3736r557089_chk'
  tag severity: 'medium'
  tag gid: 'V-203611'
  tag rid: 'SV-203611r557091_rule'
  tag stig_id: 'SRG-OS-000046-GPOS-00022'
  tag gtitle: 'SRG-OS-000046'
  tag fix_id: 'F-3736r557090_fix'
  tag 'documentable'
  tag legacy: ['V-56661', 'SV-70921']
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
