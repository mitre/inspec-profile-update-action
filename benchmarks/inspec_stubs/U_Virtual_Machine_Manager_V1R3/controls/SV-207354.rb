control 'SV-207354' do
  title 'The VMM must produce audit records containing information to establish where the events occurred.'
  desc 'Without establishing where events occurred, it is difficult to establish, correlate, and investigate the events leading up to an outage or attack.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as VMM components, guest VMs, modules, device identifiers, node names, file names, and functionality. 

Associating information about where the event occurred within the VMM provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured VMM.'
  desc 'check', 'Verify the VMM produces audit records containing information to establish where the events occurred. If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to produce audit records containing information to establish where the events occurred.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7611r365472_chk'
  tag severity: 'medium'
  tag gid: 'V-207354'
  tag rid: 'SV-207354r378622_rule'
  tag stig_id: 'SRG-OS-000039-VMM-000170'
  tag gtitle: 'SRG-OS-000039'
  tag fix_id: 'F-7611r365473_fix'
  tag 'documentable'
  tag legacy: ['SV-71141', 'V-56881']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
