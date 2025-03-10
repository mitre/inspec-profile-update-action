control 'SV-203607' do
  title 'The operating system must produce audit records containing information to establish the source of the events.'
  desc 'Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In addition to logging where events occur within the operating system, the operating system must also generate audit records that identify sources of events. Sources of operating system events include, but are not limited to, processes and services.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know the source of the event.'
  desc 'check', 'Verify the operating system produces audit records containing information to establish the source of the events. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to produce audit records containing information to establish the source of the events.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3732r557077_chk'
  tag severity: 'medium'
  tag gid: 'V-203607'
  tag rid: 'SV-203607r557079_rule'
  tag stig_id: 'SRG-OS-000040-GPOS-00018'
  tag gtitle: 'SRG-OS-000040'
  tag fix_id: 'F-3732r557078_fix'
  tag 'documentable'
  tag legacy: ['V-56653', 'SV-70913']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
