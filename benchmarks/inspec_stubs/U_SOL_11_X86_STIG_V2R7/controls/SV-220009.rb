control 'SV-220009' do
  title 'The operating system must maintain the confidentiality of information during aggregation, packaging, and transformation in preparation for transmission.'
  desc 'Ensuring that transmitted information remains confidential during aggregation, packaging, and transformation requires the operating system take feasible measures to employ transmission layer security. This requirement applies to communications across internal and external networks.'
  desc 'check', 'All remote sessions must be conducted via encrypted services and ports.

Ask the operator to document all configured external ports and protocols. If any unencrypted connections are used, this is a finding.'
  desc 'fix', 'All remote sessions must be conducted via SSH and IPsec. Ensure that SSH and IPsec are the only protocols used.'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-21719r372898_chk'
  tag severity: 'medium'
  tag gid: 'V-220009'
  tag rid: 'SV-220009r854567_rule'
  tag stig_id: 'SOL-11.1-060120'
  tag gtitle: 'SRG-OS-000425'
  tag fix_id: 'F-21718r372899_fix'
  tag 'documentable'
  tag legacy: ['SV-61033', 'V-48161']
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
