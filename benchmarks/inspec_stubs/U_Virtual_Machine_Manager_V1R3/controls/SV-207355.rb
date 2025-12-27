control 'SV-207355' do
  title 'The VMM must produce audit records containing information to establish the source of the events.'
  desc 'Without establishing the source of an event, it is difficult to establish, correlate, and investigate the events leading up to an outage or attack.

In addition to logging where events occur within the VMM, the VMM must also generate audit records that identify sources of events. Sources of VMM events include, but are not limited to, guest VMs, processes and services. 

In order to compile an accurate risk assessment, and provide forensic analysis, it is essential for security personnel to know the source of the event.'
  desc 'check', 'Verify the VMM produces audit records containing information to establish the source of the events. If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to produce audit records containing information to establish the source of the events.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7612r365475_chk'
  tag severity: 'medium'
  tag gid: 'V-207355'
  tag rid: 'SV-207355r378625_rule'
  tag stig_id: 'SRG-OS-000040-VMM-000180'
  tag gtitle: 'SRG-OS-000040'
  tag fix_id: 'F-7612r365476_fix'
  tag 'documentable'
  tag legacy: ['SV-71145', 'V-56885']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
