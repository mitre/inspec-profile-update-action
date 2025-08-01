control 'SV-219978' do
  title 'The operating system must maintain the integrity of information during aggregation, packaging, and transformation in preparation for transmission.'
  desc 'Ensuring the integrity of transmitted information requires the operating system take feasible measures to employ transmission layer security. This requirement applies to communications across internal and external networks.'
  desc 'check', 'All remote sessions must be conducted via encrypted services and ports.

Ask the operator to document all configured external ports and protocols. If any unencrypted connections are used, this is a finding.'
  desc 'fix', 'All remote sessions must be conducted via SSH and IPsec. Ensure that SSH and IPsec are the only protocols used.'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-21688r371306_chk'
  tag severity: 'medium'
  tag gid: 'V-219978'
  tag rid: 'SV-219978r854537_rule'
  tag stig_id: 'SOL-11.1-060090'
  tag gtitle: 'SRG-OS-000425'
  tag fix_id: 'F-21687r371307_fix'
  tag 'documentable'
  tag legacy: ['V-48171', 'SV-61043']
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
