control 'SV-203605' do
  title 'The operating system must produce audit records containing information to establish when (date and time) the events occurred.'
  desc 'Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know when events occurred (date and time).

Associating event types with detected events in the operating system audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured operating system.'
  desc 'check', 'Verify the operating system produces audit records containing information to establish when (date and time) the events occurred. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to produce audit records containing information to establish when (date and time) the events occurred.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3730r557071_chk'
  tag severity: 'medium'
  tag gid: 'V-203605'
  tag rid: 'SV-203605r557073_rule'
  tag stig_id: 'SRG-OS-000038-GPOS-00016'
  tag gtitle: 'SRG-OS-000038'
  tag fix_id: 'F-3730r557072_fix'
  tag 'documentable'
  tag legacy: ['V-56649', 'SV-70909']
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
