control 'SV-26991' do
  title 'The system package management tool must cryptographically verify the authenticity of software packages during installation.'
  desc 'To prevent the installation of software from unauthorized sources, the system package management tool must use cryptographic algorithms to verify the packages are authentic.'
  desc 'fix', 'Edit /var/sadm/install/admin/default and set the authentication setting to quit.'
  impact 0.3
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'low'
  tag gid: 'V-22588'
  tag rid: 'SV-26991r1_rule'
  tag stig_id: 'GEN008800'
  tag gtitle: 'GEN008800'
  tag fix_id: 'F-24257r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000351']
  tag nist: ['CM-5 (3)']
end
