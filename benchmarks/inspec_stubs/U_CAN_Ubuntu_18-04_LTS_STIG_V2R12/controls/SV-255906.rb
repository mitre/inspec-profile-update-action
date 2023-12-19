control 'SV-255906' do
  title 'The Ubuntu operating system SSH server must be configured to use only FIPS-validated key exchange algorithms.'
  desc 'Without cryptographic integrity protections provided by FIPS-validated cryptographic algorithms, information can be viewed and altered by unauthorized users without detection.

The system will attempt to use the first algorithm presented by the client that matches the server list. Listing the values "strongest to weakest" is a method to ensure the use of the strongest algorithm available to secure the SSH connection.'
  desc 'check', 'Verify that the SSH server is configured to use only FIPS-validated key exchange algorithms:

     $ sudo grep -i kexalgorithms /etc/ssh/sshd_config
     KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256
 
If "KexAlgorithms" is not configured, is commented out, or does not contain only the algorithms "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256" in exact order, this is a finding.'
  desc 'fix', 'Configure the SSH server to use only FIPS-validated key exchange algorithms by adding or modifying the following line in "/etc/ssh/sshd_config":

     KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256

Restart the "sshd" service for changes to take effect:

     $ sudo systemctl restart sshd'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-59583r880887_chk'
  tag severity: 'medium'
  tag gid: 'V-255906'
  tag rid: 'SV-255906r880889_rule'
  tag stig_id: 'UBTU-18-010421'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-59526r880888_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
