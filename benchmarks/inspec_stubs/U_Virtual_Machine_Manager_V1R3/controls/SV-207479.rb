control 'SV-207479' do
  title 'The VMM must require devices to re-authenticate when changing authenticators.'
  desc 'Without re-authentication, devices may access resources or perform tasks for which they do not have authorization. 

When VMMs provide the capability to change device authenticators, it is critical the device re-authenticate.

This requirement is applicable to devices capable of authentication.'
  desc 'check', 'Verify the VMM requires devices to re-authenticate when changing authenticators.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to require devices to re-authenticate when changing authenticators.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7736r365841_chk'
  tag severity: 'medium'
  tag gid: 'V-207479'
  tag rid: 'SV-207479r854653_rule'
  tag stig_id: 'SRG-OS-000374-VMM-001500'
  tag gtitle: 'SRG-OS-000374'
  tag fix_id: 'F-7736r365842_fix'
  tag 'documentable'
  tag legacy: ['SV-71419', 'V-57159']
  tag cci: ['CCI-002039']
  tag nist: ['IA-11']
end
