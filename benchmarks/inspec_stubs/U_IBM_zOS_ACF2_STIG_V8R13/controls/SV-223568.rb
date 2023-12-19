control 'SV-223568' do
  title 'IBM z/OS must use ICSF or SAF Key Rings for key management.'
  desc 'If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure.

The cornerstone of the PKI is the private key used to encrypt or digitally sign information.

If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user.

Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys.

'
  desc 'check', 'Any keys or Certificates must be managed in ICSF or the external security manager and not in UNIX files.

From the ISPF Command Shell enter:
OMVS
enter
find / -name *.kdb
and
find / -name *jks
If any files are found, this is a finding.'
  desc 'fix', 'Define all Keys/Certificates to  ICSF or the security database. Remove any .kdb and .jks files.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25241r810995_chk'
  tag severity: 'medium'
  tag gid: 'V-223568'
  tag rid: 'SV-223568r811030_rule'
  tag stig_id: 'ACF2-OS-000330'
  tag gtitle: 'SRG-OS-000067-GPOS-00035'
  tag fix_id: 'F-25229r811029_fix'
  tag satisfies: ['SRG-OS-000067-GPOS-00035', 'SRG-OS-000068-GPOS-00036']
  tag 'documentable'
  tag legacy: ['V-97841', 'SV-106945']
  tag cci: ['CCI-000186', 'CCI-000187']
  tag nist: ['IA-5 (2) (a) (1)', 'IA-5 (2) (a) (2)']
end
