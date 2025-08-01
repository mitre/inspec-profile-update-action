control 'SV-26263' do
  title 'The system package management tool must cryptographically verify the authenticity of software packages during installation.'
  desc 'To prevent the installation of software from unauthorized sources, the system package management tool must use cryptographic algorithms to verify the packages are authentic.'
  desc 'check', 'Determine if the system package management tool cryptographically verifies the authenticity of packages during installation. If it does not, this is a finding.'
  desc 'fix', 'If possible, configure the system package management tool to cryptographically verify the authenticity of packages during installation.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29323r1_chk'
  tag severity: 'low'
  tag gid: 'V-22588'
  tag rid: 'SV-26263r1_rule'
  tag stig_id: 'GEN008800'
  tag gtitle: 'GEN008800'
  tag fix_id: 'F-26355r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000351']
  tag nist: ['CM-5 (3)']
end
