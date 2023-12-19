control 'SV-225052' do
  title 'Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.'
  desc 'Certain encryption types are no longer considered secure. The DES and RC4 encryption suites must not be used for Kerberos encryption.

Note: Organizations with domain controllers running earlier versions of Windows where RC4 encryption is enabled, selecting "The other domain supports Kerberos AES Encryption" on domain trusts, may be required to allow client communication across the trust relationship.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters\\

Value Name: SupportedEncryptionTypes

Value Type: REG_DWORD
Value: 0x7ffffff8 (2147483640)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: Configure encryption types allowed for Kerberos" to "Enabled" with only the following selected:

AES128_HMAC_SHA1
AES256_HMAC_SHA1
Future encryption types   

Note: Organizations with domain controllers running earlier versions of Windows where RC4 encryption is enabled, selecting "The other domain supports Kerberos AES Encryption" on domain trusts, may be required to allow client communication across the trust relationship.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26743r466058_chk'
  tag severity: 'medium'
  tag gid: 'V-225052'
  tag rid: 'SV-225052r569186_rule'
  tag stig_id: 'WN16-SO-000350'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-26731r466059_fix'
  tag 'documentable'
  tag legacy: ['V-73685', 'SV-88349']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
