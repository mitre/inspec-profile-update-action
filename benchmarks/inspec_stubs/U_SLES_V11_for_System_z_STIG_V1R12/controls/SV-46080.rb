control 'SV-46080' do
  title 'The system package management tool must cryptographically verify the authenticity of software packages during installation.'
  desc 'To prevent the installation of software from unauthorized sources, the system package management tool must use cryptographic algorithms to verify the packages are authentic.'
  desc 'check', 'Ensure that the suse-build-key package is installed and the build-key file exists:
# rpm –ql suse-build-key
# ls –l /usr/lib/rpm/gnupg/suse-build-key.gpg

Ensure that the value of the CHECK_SIGNATURES variable is set to “yes”
# grep –i check_signature /etc/sysconfig/security
If the /usr/lib/rpm/gnupg/suse-build-key.gpg file does not exist or CHECK_SIGNATURES is not set to “yes”, this is a finding.'
  desc 'fix', 'Install the suse-build-key package from the vendor repository
# rpm –Uvh suse-build-key-<current version>.noarch.rpm && SuSEconfig

Use the YaST System > “/etc/sysconfig Editor” module to set the value of the CHECK_SIGNATURES variable to “yes”.  It can be found by expanding the plus signs for System > Security > PolicyKit'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43338r2_chk'
  tag severity: 'low'
  tag gid: 'V-22588'
  tag rid: 'SV-46080r2_rule'
  tag stig_id: 'GEN008800'
  tag gtitle: 'GEN008800'
  tag fix_id: 'F-39426r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000351']
  tag nist: ['CM-5 (3)']
end
