control 'SV-226327' do
  title 'Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.'
  desc 'Certain encryption types are no longer considered secure. The DES and RC4 encryption suites must not be used for Kerberos encryption.

Note: Removing the previously allowed RC4_HMAC_MD5 encryption suite may have operational impacts and must be thoroughly tested for the environment before changing. This includes but is not limited to parent\\child trusts where RC4 is still enabled; selecting "The other domain supports Kerberos AES Encryption" may be required on the domain trusts to allow client communication across the trust relationship.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters\\

Value Name: SupportedEncryptionTypes

Value Type: REG_DWORD
Value: 0x7ffffff8 (2147483640)

Note: Removing the previously allowed RC4_HMAC_MD5 encryption suite may have operational impacts and must be thoroughly tested for the environment before changing. This includes but is not limited to parent\\child trusts where RC4 is still enabled; selecting "The other domain supports Kerberos AES Encryption" may be required on the domain trusts to allow client communication across the trust relationship.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: Configure encryption types allowed for Kerberos" to "Enabled" with only the following selected:

AES128_HMAC_SHA1
AES256_HMAC_SHA1
Future encryption types

Note: Removing the previously allowed RC4_HMAC_MD5 encryption suite may have operational impacts and must be thoroughly tested for the environment before changing. This includes but is not limited to parent\\child trusts where RC4 is still enabled; selecting "The other domain supports Kerberos AES Encryption" may be required on the domain trusts to allow client communication across the trust relationship.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28029r476825_chk'
  tag severity: 'medium'
  tag gid: 'V-226327'
  tag rid: 'SV-226327r794539_rule'
  tag stig_id: 'WN12-SO-000064'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-28017r476826_fix'
  tag 'documentable'
  tag legacy: ['V-21954', 'SV-53179']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
