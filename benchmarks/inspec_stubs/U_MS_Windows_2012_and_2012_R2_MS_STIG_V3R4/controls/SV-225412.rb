control 'SV-225412' do
  title 'The setting to allow Microsoft accounts to be optional for modern style apps must be enabled (Windows 2012 R2).'
  desc 'Control of credentials and the system must be maintained within the enterprise.  Enabling this setting allows enterprise credentials to be used with modern style apps that support this, instead of Microsoft accounts.'
  desc 'check', 'This requirement is NA for the initial release of Windows 2012.  It is applicable to Windows 2012 R2.

Verify the registry value below.  If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System

Value Name: MSAOptional

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'This requirement is NA for the initial release of Windows 2012.  It is applicable to Windows 2012 R2.

Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> App Runtime -> "Allow Microsoft accounts to be optional" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27111r471578_chk'
  tag severity: 'low'
  tag gid: 'V-225412'
  tag rid: 'SV-225412r569185_rule'
  tag stig_id: 'WN12-CC-000141'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27099r471579_fix'
  tag 'documentable'
  tag legacy: ['SV-56353', 'V-43241']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
