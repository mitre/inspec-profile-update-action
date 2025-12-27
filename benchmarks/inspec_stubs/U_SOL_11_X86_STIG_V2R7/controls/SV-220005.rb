control 'SV-220005' do
  title 'The operating system must employ cryptographic mechanisms to recognize changes to information during transmission unless otherwise protected by alternative physical measures.'
  desc 'Ensuring that transmitted information is not altered during transmission requires the operating system take feasible measures to employ transmission layer security. This requirement applies to communications across internal and external networks.'
  desc 'check', 'All remote sessions must be conducted via encrypted services and ports.

Ask the operator to document all configured external ports and protocols. If any unencrypted connections are used, this is a finding.'
  desc 'fix', 'All remote sessions must be conducted via SSH and IPsec. Ensure that SSH and IPsec are the only protocols used.'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-21715r372886_chk'
  tag severity: 'medium'
  tag gid: 'V-220005'
  tag rid: 'SV-220005r877040_rule'
  tag stig_id: 'SOL-11.1-060080'
  tag gtitle: 'SRG-OS-000424'
  tag fix_id: 'F-21714r372887_fix'
  tag 'documentable'
  tag legacy: ['SV-61047', 'V-48175']
  tag cci: ['CCI-002421']
  tag nist: ['SC-8 (1)']
end
