control 'SV-26990' do
  title 'The system package management tool must cryptographically verify the authenticity of software packages during installation.'
  desc 'To prevent the installation of software from unauthorized sources, the system package management tool must use cryptographic algorithms to verify the packages are authentic.'
  desc 'fix', 'Edit the YUM configuration containing "gpgcheck=0" and set the value to "1".'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag severity: 'low'
  tag gid: 'V-22588'
  tag rid: 'SV-26990r2_rule'
  tag stig_id: 'GEN008800'
  tag gtitle: 'GEN008800'
  tag fix_id: 'F-24256r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000351']
  tag nist: ['CM-5 (3)']
end
