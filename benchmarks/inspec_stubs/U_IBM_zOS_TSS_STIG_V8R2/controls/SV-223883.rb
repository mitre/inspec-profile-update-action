control 'SV-223883' do
  title 'IBM z/OS for PKI-based authentication must use the ESM to store keys.'
  desc 'If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure.

The cornerstone of the PKI is the private key used to encrypt or digitally sign information.

If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user.

Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys.'
  desc 'check', 'From the ISPF Command Shell enter:
OMVS
enter
find / -name *.kdb
and 
Find / -name *.jks
If any files are found, this is a finding.'
  desc 'fix', 'Define all Keys/Certificates to the security database.

Remove all .kdb and .jks key files.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25556r695264_chk'
  tag severity: 'medium'
  tag gid: 'V-223883'
  tag rid: 'SV-223883r695461_rule'
  tag stig_id: 'TSS0-ES-000100'
  tag gtitle: 'SRG-OS-000067-GPOS-00035'
  tag fix_id: 'F-25544r695265_fix'
  tag 'documentable'
  tag legacy: ['V-98473', 'SV-107577']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
