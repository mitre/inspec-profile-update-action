control 'SV-219976' do
  title 'The operating system must protect the integrity of transmitted information.'
  desc 'Ensuring the integrity of transmitted information requires the operating system take feasible measures to employ transmission layer security. This requirement applies to communications across internal and external networks.'
  desc 'check', 'All remote sessions must be conducted via encrypted services and ports.

Ask the operator to document all configured external ports and protocols. If any unencrypted connections are used, this is a finding.'
  desc 'fix', 'All remote sessions must be conducted via SSH and IPsec. Ensure that SSH and IPsec are the only protocols used.'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-21686r371300_chk'
  tag severity: 'medium'
  tag gid: 'V-219976'
  tag rid: 'SV-219976r603267_rule'
  tag stig_id: 'SOL-11.1-060070'
  tag gtitle: 'SRG-OS-000423'
  tag fix_id: 'F-21685r371301_fix'
  tag 'documentable'
  tag legacy: ['SV-61051', 'V-48179']
  tag cci: ['CCI-001127']
  tag nist: ['SC-8']
end
