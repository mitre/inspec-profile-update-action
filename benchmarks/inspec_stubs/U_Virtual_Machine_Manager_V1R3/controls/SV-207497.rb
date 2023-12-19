control 'SV-207497' do
  title 'The VMM must maintain a separate execution domain for each guest VM.'
  desc 'VMMs can maintain separate execution domains for each executing guest VM by assigning each guest VM a separate address space. Each VMM guest VM has a distinct address space so that communication between guest VMs is performed in a manner controlled through the security functions of the VMM, and one guest VM cannot modify the executing code of another guest VM. This capability is available in most commercial VMMs that employ virtualization processor technologies.'
  desc 'check', 'Verify the VMM maintains a separate execution domain for each guest VM.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to maintain a separate execution domain for each guest VM.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7754r365895_chk'
  tag severity: 'medium'
  tag gid: 'V-207497'
  tag rid: 'SV-207497r854671_rule'
  tag stig_id: 'SRG-OS-000408-VMM-001680'
  tag gtitle: 'SRG-OS-000408'
  tag fix_id: 'F-7754r365896_fix'
  tag 'documentable'
  tag legacy: ['SV-71555', 'V-57295']
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']
end
