control 'SV-239921' do
  title 'The Cisco ASA must be configured to audit the execution of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', 'Review the Cisco ASA configuration to verify that it is compliant with this requirement. The configuration example below will log all configuration changes.
  
logging enable
logging buffered informational

Note: The ASA will log all EXEC-mode commands.

If the Cisco ASA is not configured to log all configuration changes, this is a finding.'
  desc 'fix', 'Configure the Cisco ASA to log all configuration changes as shown in the following example.

ASA(config)# logging enable
ASA(config)# logging buffered informational
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43154r666124_chk'
  tag severity: 'medium'
  tag gid: 'V-239921'
  tag rid: 'SV-239921r666126_rule'
  tag stig_id: 'CASA-ND-000910'
  tag gtitle: 'SRG-APP-000343-NDM-000289'
  tag fix_id: 'F-43113r666125_fix'
  tag 'documentable'
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
