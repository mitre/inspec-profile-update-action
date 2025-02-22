control 'SV-234489' do
  title 'The UEM server must audit the execution of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse, and identify the risk from insider threats and the advanced persistent threat. 

Satisfies:FAU_GEN.1.1(1), b.'
  desc 'check', 'Verify the UEM server audits the execution of privileged functions.

If the UEM server does not audit the execution of privileged functions, this is a finding.'
  desc 'fix', 'Configure the UEM server to audit the execution of privileged functions.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37674r615110_chk'
  tag severity: 'medium'
  tag gid: 'V-234489'
  tag rid: 'SV-234489r617355_rule'
  tag stig_id: 'SRG-APP-000343-UEM-000216'
  tag gtitle: 'SRG-APP-000343'
  tag fix_id: 'F-37639r615111_fix'
  tag 'documentable'
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
