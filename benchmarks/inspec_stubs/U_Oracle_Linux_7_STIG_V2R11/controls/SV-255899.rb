control 'SV-255899' do
  title 'The Oracle Linux operating system SSH server must be configured to use only FIPS-validated key exchange algorithms.'
  desc 'The use of FIPS-validated cryptographic algorithms is enforced by enabling kernel FIPS mode. In the event that kernel FIPS mode is disabled, the use of nonvalidated cryptographic algorithms will be permitted systemwide. The SSH server configuration must manually define only FIPS-validated key exchange algorithms to prevent the use of nonvalidated algorithms.'
  desc 'check', 'Verify that the SSH server is configured to use only FIPS-validated key exchange algorithms:

     $ sudo grep -i kexalgorithms /etc/ssh/sshd_config
     KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256
 
If "KexAlgorithms" is not configured, is commented out, or does not contain only the algorithms "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256" in exact order, this is a finding.'
  desc 'fix', 'Configure the SSH server to use only FIPS-validated key exchange algorithms by adding or modifying the following line in "/etc/ssh/sshd_config":

     KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256

Restart the "sshd" service for changes to take effect:

     $ sudo systemctl restart sshd'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-59576r880580_chk'
  tag severity: 'medium'
  tag gid: 'V-255899'
  tag rid: 'SV-255899r880582_rule'
  tag stig_id: 'OL07-00-040712'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-59519r880581_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
