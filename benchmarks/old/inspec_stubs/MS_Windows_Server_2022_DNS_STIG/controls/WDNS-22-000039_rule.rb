control 'WDNS-22-000039_rule' do
  title 'The Windows 2022 DNS Server must be configured to enforce authorized access to the corresponding private key.'
  desc 'The cornerstone of the PKI is the private key used to encrypt or digitally sign information. If the private key is stolen, this will lead to the compromise of the authentication and nonrepudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user. Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys.

SIG(0) is used for server-to-server authentication for DNS transactions, and it uses PKI-based authentication. In cases where SIG(0) is being used instead of TSIG (which uses a shared key, not PKI-based authentication), this requirement is applicable.'
  desc 'check', 'Access Windows Explorer.

Navigate to the following location:

%ALLUSERSPROFILE%\\Microsoft\\Crypto

Note: If the folder above does not exist, this check is not applicable.

Verify the permissions on the keys folder, subfolders, and files are limited to SYSTEM and Administrators FULL CONTROL.

If any other user or group has greater than READ privileges to the %ALLUSERSPROFILE%\\Microsoft\\Crypto folder, subfolders and files, this is a finding.'
  desc 'fix', 'Access Windows Explorer.

Navigate to the following location:

%ALLUSERSPROFILE%\\Microsoft\\Crypto

Modify permissions on the keys folder, subfolders, and files to be limited to SYSTEM and Administrators FULL CONTROL to limit all other users/groups to READ.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000039_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000039'
  tag rid: 'WDNS-22-000039_rule'
  tag stig_id: 'WDNS-22-000039'
  tag gtitle: 'SRG-APP-000176-DNS-000017'
  tag fix_id: 'F-WDNS-22-000039_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
