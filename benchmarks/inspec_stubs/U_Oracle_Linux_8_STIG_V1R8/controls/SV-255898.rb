control 'SV-255898' do
  title 'OL 8 SSH server must be configured to use only FIPS-validated key exchange algorithms.'
  desc 'Without cryptographic integrity protections provided by FIPS-validated cryptographic algorithms, information can be viewed and altered by unauthorized users without detection.

OL 8 incorporates system-wide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the /etc/sysconfig/sshd file. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/opensshserver.config file.

The system will attempt to use the first algorithm presented by the client that matches the server list. Listing the values "strongest to weakest" is a method to ensure the use of the strongest algorithm available to secure the SSH connection.'
  desc 'check', %q(Verify that the SSH server is configured to use only FIPS-validated key exchange algorithms:

     $ sudo grep -i kexalgorithms /etc/crypto-policies/back-ends/opensshserver.config

     CRYPTO_POLICY='-oKexAlgorithms=ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512'

If the entries following "KexAlgorithms" have any algorithms defined other than "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512", appear in a different order than shown, or are missing or commented out, this is a finding.)
  desc 'fix', 'Configure the SSH server to use only FIPS-validated key exchange algorithms by adding or modifying the following line in "/etc/crypto-policies/back-ends/opensshserver.config":

-oKexAlgorithms=ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

A reboot is required for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-59575r917915_chk'
  tag severity: 'medium'
  tag gid: 'V-255898'
  tag rid: 'SV-255898r917916_rule'
  tag stig_id: 'OL08-00-040342'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-59518r880543_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
