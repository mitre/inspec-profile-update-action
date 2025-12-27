control 'SV-226182' do
  title 'Trusted app installation must be enabled to allow for signed enterprise line of business apps.'
  desc 'Enabling trusted app installation allows for enterprise line of business Windows 8 type apps.   A trusted app package is one that is signed with a certificate chain that can be successfully validated in the enterprise.  Configuring this ensures enterprise line of business apps are accessible.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\Appx\\

Value Name: AllowAllTrustedApps

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> App Package Deployment  -> "Allow all trusted apps to install" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27884r475869_chk'
  tag severity: 'low'
  tag gid: 'V-226182'
  tag rid: 'SV-226182r794437_rule'
  tag stig_id: 'WN12-CC-000070'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27872r475870_fix'
  tag 'documentable'
  tag legacy: ['V-36697', 'SV-51738']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
