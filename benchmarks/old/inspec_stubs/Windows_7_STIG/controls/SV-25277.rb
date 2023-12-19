control 'SV-25277' do
  title 'The use of DES encryption suites must not be allowed for Kerberos encryption.'
  desc 'Certain encryption types are no longer considered secure.  This setting configures a minimum encryption type for Kerberos, preventing the use of the DES encryption suites.'
  desc 'check', 'Review the value to the following registry key to verify the DES_CBC_CRC and DES_CBC_MD5 encryption suites are not allowed.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters\\
Value Name:  SupportedEncryptionTypes
Type:  REG_DWORD

The values are determined by the selection of encryption suites in the policy "Network Security: Configure encryption types allowed for Kerberos".

Due to the various possible combinations, it is not possible to include all acceptable values as viewed directly in the registry.

The value must be converted to binary to determine configuration of specific bits.  This will determine whether this is a finding.

Note the value for the registry key.
For example when all suites, including the DES suites are selected, the value will be "0x7fffffff (2147483647)".

Open the Windows calculator (Run/Search for "calc").
Select "View", then "Programmer".
Select "Dword" and either "Hex" or "Dec".
Enter the appropriate form of the value found for the registry key (e.g., Hex - enter 0x7fffffff, Dec - enter 2147483647).
Select "Bin".

The returned value may vary in length, up to 32 characters.

If either of the 2 right most characters are "1", this is a finding.

If both of the 2 right most characters are "0", this is not a finding.'
  desc 'fix', 'Configure the policy for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: Configure encryption types allowed for Kerberos" to "Enabled" with only the following selected:

RC4_HMAC_MD5
AES128_HMAC_SHA1
AES256_HMAC_SHA1
Future encryption types

Options such as RC4_HMAC_MD5 may also be excluded to align with STIGs for later Windows versions.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-78963r2_chk'
  tag severity: 'medium'
  tag gid: 'V-21954'
  tag rid: 'SV-25277r3_rule'
  tag gtitle: 'Kerberos Encryption Types'
  tag fix_id: 'F-86121r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
