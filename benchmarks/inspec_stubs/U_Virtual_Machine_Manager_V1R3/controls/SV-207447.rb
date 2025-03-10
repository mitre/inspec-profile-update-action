control 'SV-207447' do
  title 'The VMM must audit the execution of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally, by authorized users, or by unauthorized external entities that have compromised VMM accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', 'Verify the VMM audits the execution of privileged functions.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to audit the execution of privileged functions.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7704r365751_chk'
  tag severity: 'medium'
  tag gid: 'V-207447'
  tag rid: 'SV-207447r854620_rule'
  tag stig_id: 'SRG-OS-000327-VMM-001170'
  tag gtitle: 'SRG-OS-000327'
  tag fix_id: 'F-7704r365752_fix'
  tag 'documentable'
  tag legacy: ['SV-71355', 'V-57095']
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
