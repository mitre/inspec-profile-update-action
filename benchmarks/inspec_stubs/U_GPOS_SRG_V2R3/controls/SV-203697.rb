control 'SV-203697' do
  title 'The operating system must audit the execution of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', 'Verify that the operating system audits the execution of privileged functions. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to audit the execution of privileged functions.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3822r375038_chk'
  tag severity: 'medium'
  tag gid: 'V-203697'
  tag rid: 'SV-203697r379600_rule'
  tag stig_id: 'SRG-OS-000327-GPOS-00127'
  tag gtitle: 'SRG-OS-000327'
  tag fix_id: 'F-3822r375039_fix'
  tag 'documentable'
  tag legacy: ['V-57235', 'SV-71495']
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
