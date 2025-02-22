control 'SV-215321' do
  title 'AIX SSH private host key files must have mode 0600 or less permissive.'
  desc 'If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure.

The cornerstone of the PKI is the private key used to encrypt or digitally sign information.

If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user.

Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys.'
  desc 'check', 'Check the permissions for SSH private host key files: 
# ls -lL /etc/ssh/*key 

The above command should yield the following output:
-rw-------    1 root     system          668 Jan 18 2017  /etc/ssh/ssh_host_dsa_key
-rw-------    1 root     system          227 Jan 18 2017  /etc/ssh/ssh_host_ecdsa_key
-rw-------    1 root     system          965 Jan 18 2017  /etc/ssh/ssh_host_key
-rw-------    1 root     system         1675 Jan 18 2017  /etc/ssh/ssh_host_rsa_key

If any file has a mode more permissive than "0600", this is a finding.'
  desc 'fix', 'Change the permissions for the SSH private host key files:
# chmod 0600 /etc/ssh/*key'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16519r294414_chk'
  tag severity: 'medium'
  tag gid: 'V-215321'
  tag rid: 'SV-215321r508663_rule'
  tag stig_id: 'AIX7-00-003004'
  tag gtitle: 'SRG-OS-000067-GPOS-00035'
  tag fix_id: 'F-16517r294415_fix'
  tag 'documentable'
  tag legacy: ['V-91279', 'SV-101377']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
