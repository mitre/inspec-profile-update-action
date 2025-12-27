control 'SV-87389' do
  title 'WDigest Authentication must be disabled.'
  desc 'When the WDigest Authentication protocol is enabled, plain text passwords are stored in the Local Security Authority Subsystem Service (LSASS) exposing them to theft.  This setting will prevent WDigest from storing credentials in memory.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Wdigest\\

Value Name: UseLogonCredential

Type: REG_DWORD
Value: 0x00000000 (0)

Note: Microsoft Security Advisory update 2871997 is required for this setting to be effective on Windows 2008 R2.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >> "WDigest Authentication (disabling may require KB2871997)" to "Disabled".

Note: Microsoft Security Advisory update 2871997 is required for this setting to be effective on Windows 2008 R2.

This policy setting requires the installation of the SecGuide custom templates included with the STIG package. "SecGuide.admx" and "SecGuide.adml" must be copied to the \\Windows\\PolicyDefinitions and \\Windows\\PolicyDefinitions\\en-US directories respectively.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-72899r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72753'
  tag rid: 'SV-87389r1_rule'
  tag stig_id: 'WINCC-000150'
  tag gtitle: 'WINCC-000150'
  tag fix_id: 'F-79161r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
