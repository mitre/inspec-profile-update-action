control 'SV-202094' do
  title 'The network device must audit the execution of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', 'Determine if the network device audits the execution of privileged functions. This requirement may be verified by demonstration, configuration review, or validated test results. If the network device does not audit the execution of privileged functions, this is a finding.'
  desc 'fix', 'Configure the network device to audit the execution of privileged functions.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2220r381923_chk'
  tag severity: 'medium'
  tag gid: 'V-202094'
  tag rid: 'SV-202094r399784_rule'
  tag stig_id: 'SRG-APP-000343-NDM-000289'
  tag gtitle: 'SRG-APP-000343'
  tag fix_id: 'F-2221r381924_fix'
  tag 'documentable'
  tag legacy: ['SV-69313', 'V-55067']
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
