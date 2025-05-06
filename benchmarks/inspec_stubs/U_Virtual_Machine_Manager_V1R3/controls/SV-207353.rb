control 'SV-207353' do
  title 'The VMM must produce audit records containing information to establish when (date and time) the events occurred.'
  desc 'Without establishing when events occurred, it is difficult to establish, correlate, and investigate the events leading up to an outage or attack.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know when events occurred (date and time). 

Associating event types with detected events in the VMM audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured VMM.'
  desc 'check', 'Verify the VMM produces audit records containing information to establish when (date and time) the events occurred. If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to produce audit records containing information to establish when (date and time) the events occurred.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7610r365469_chk'
  tag severity: 'medium'
  tag gid: 'V-207353'
  tag rid: 'SV-207353r378619_rule'
  tag stig_id: 'SRG-OS-000038-VMM-000160'
  tag gtitle: 'SRG-OS-000038'
  tag fix_id: 'F-7610r365470_fix'
  tag 'documentable'
  tag legacy: ['SV-71139', 'V-56879']
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
