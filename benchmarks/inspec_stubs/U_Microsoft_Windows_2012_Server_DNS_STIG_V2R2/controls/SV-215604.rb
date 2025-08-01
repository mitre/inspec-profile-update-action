control 'SV-215604' do
  title 'The Windows 2012 DNS Server must be configured to enforce authorized access to the corresponding private key.'
  desc 'The cornerstone of the PKI is the private key used to encrypt or digitally sign information. If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user. Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys.

SIG(0) is used for server-to-server authentication for DNS transactions, and it uses PKI-based authentication. So, in cases where SIG(0) is being used instead of TSIG (which uses a shared key, not PKI-based authentication), this requirement is applicable.'
  desc 'check', "Access Windows Explorer.

Navigate to the following location:

%ALLUSERSPROFILE%\\Microsoft\\Crypto
Note: If the %ALLUSERSPROFILE%\\Microsoft\\Crypto folder doesn't exist, this is not applicable.

Verify the permissions on the keys folder, sub-folders, and files are limited to SYSTEM and Administrators FULL CONTROL.

If any other user or group has greater than READ privileges to the %ALLUSERSPROFILE%\\Microsoft\\Crypto folder, sub-folders and files, this is a finding."
  desc 'fix', 'Access Windows Explorer.

Navigate to the following location:

%ALLUSERSPROFILE%\\Microsoft\\Crypto

Modify permissions on the keys folder, sub-folders, and files to be limited to SYSTEM and Administrators FULL CONTROL and to all other Users/Groups to READ.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16798r314287_chk'
  tag severity: 'medium'
  tag gid: 'V-215604'
  tag rid: 'SV-215604r561297_rule'
  tag stig_id: 'WDNS-IA-000006'
  tag gtitle: 'SRG-APP-000176-DNS-000017'
  tag fix_id: 'F-16796r314288_fix'
  tag 'documentable'
  tag legacy: ['SV-73071', 'V-58641']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
