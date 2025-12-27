control 'SV-218730' do
  title 'The system package management tool must cryptographically verify the authenticity of software packages during installation.'
  desc 'To prevent the installation of software from unauthorized sources, the system package management tool must use cryptographic algorithms to verify the packages are authentic.'
  desc 'check', 'Verify YUM signature validation is not disabled.
# grep gpgcheck /etc/yum.conf /etc/yum.repos.d/*

If no results are returned, or the returned "gpgcheck" settings are not equal to "1", this is a finding.'
  desc 'fix', 'Edit the YUM configuration containing "gpgcheck=0" and set the value to "1".'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20205r562960_chk'
  tag severity: 'low'
  tag gid: 'V-218730'
  tag rid: 'SV-218730r603259_rule'
  tag stig_id: 'GEN008800'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-20203r562961_fix'
  tag 'documentable'
  tag legacy: ['V-22588', 'SV-63027']
  tag cci: ['CCI-000351', 'CCI-001749']
  tag nist: ['CM-5 (3)', 'CM-5 (3)']
end
