control 'SV-70911' do
  title 'The operating system must produce audit records containing information to establish where the events occurred.'
  desc 'Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as operating system components, modules, device identifiers, node names, file names, and functionality.

Associating information about where the event occurred within the operating system provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured operating system.'
  desc 'check', 'Verify the operating system produces audit records containing information to establish where the events occurred. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to produce audit records containing information to establish where the events occurred.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57221r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56651'
  tag rid: 'SV-70911r1_rule'
  tag stig_id: 'SRG-OS-000039-GPOS-00017'
  tag gtitle: 'SRG-OS-000039-GPOS-00017'
  tag fix_id: 'F-61547r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
