control 'SV-48321' do
  title 'Trusted app installation must be enabled to allow for signed enterprise line of business apps.'
  desc 'Enabling trusted app installation allows for enterprise line of business Windows 8 type apps.   A trusted app package is one that is signed with a certificate chain that can be successfully validated in the enterprise.  Configuring this ensures enterprise line of business apps are accessible.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\Appx\\

Value Name: AllowAllTrustedApps

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> App Package Deployment  -> " Allow all trusted apps to install " to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44993r1_chk'
  tag severity: 'low'
  tag gid: 'V-36697'
  tag rid: 'SV-48321r2_rule'
  tag stig_id: 'WN08-CC-000070'
  tag gtitle: 'WINCC-000070'
  tag fix_id: 'F-41453r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
