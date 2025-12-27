control 'SV-225415' do
  title 'WDigest Authentication must be disabled.'
  desc 'When the WDigest Authentication protocol is enabled, plain text passwords are stored in the Local Security Authority Subsystem Service (LSASS) exposing them to theft.  This setting will prevent WDigest from storing credentials in memory.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Wdigest\\

Value Name: UseLogonCredential

Type: REG_DWORD
Value: 0x00000000 (0)

Note: Microsoft Security Advisory update 2871997 is required for this setting to be effective on Windows 2012.  It is not required for Windows 2012 R2.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >> "WDigest Authentication (disabling may require KB2871997)" to "Disabled".

Note: Microsoft Security Advisory update 2871997 is required for this setting to be effective on Windows 2012.  It is not required for Windows 2012 R2.

This policy setting requires the installation of the SecGuide custom templates included with the STIG package. "SecGuide.admx" and "SecGuide.adml" must be copied to the \\Windows\\PolicyDefinitions and \\Windows\\PolicyDefinitions\\en-US directories respectively.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27114r471587_chk'
  tag severity: 'medium'
  tag gid: 'V-225415'
  tag rid: 'SV-225415r569185_rule'
  tag stig_id: 'WN12-CC-000150'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27102r471588_fix'
  tag 'documentable'
  tag legacy: ['SV-87391', 'V-72753']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
