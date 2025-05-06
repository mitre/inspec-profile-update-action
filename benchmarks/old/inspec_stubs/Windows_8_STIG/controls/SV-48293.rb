control 'SV-48293' do
  title 'Users must only be allowed to point and print to machines in their forest.'
  desc 'Uncontrolled system updates can introduce issues to a system.  Obtaining update components from an outside source may also potentially provide sensitive information outside of the enterprise.  Configuring this setting will restrict, but allow users to obtain print drivers for printers in their forest.'
  desc 'check', 'If the following registry values do not exist or are not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint \\

Value Name: InForest
Type: REG_DWORD
Value: 1

Value Name: NoWarningNoElevationOnInstall
Type: REG_DWORD
Value: 1

Value Name: UpdatePromptSettings
Type: REG_DWORD
Value: 2'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Printers -> "Point and Print Restrictions" to "Enabled" with "Users can only point and print to machines in their forest" selected and the following Security Prompts: 

When installing Drivers for a new connection:
Do not show warning or elevation prompt.

When updating drivers for an existing connection:
Do not show warning or elevation prompt.'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44971r1_chk'
  tag severity: 'low'
  tag gid: 'V-36676'
  tag rid: 'SV-48293r2_rule'
  tag stig_id: 'WN08-CC-000017'
  tag gtitle: 'WN08-CC-000017'
  tag fix_id: 'F-41428r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
