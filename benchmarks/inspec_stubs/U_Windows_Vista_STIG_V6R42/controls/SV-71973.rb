control 'SV-71973' do
  title 'The system must be configured to permit the default consent levels of Windows Error Reporting to override any other consent policy setting.'
  desc 'This setting determines the behavior of the "Configure Default Consent" setting in relation to custom consent settings.  Enabling this allows the default consent levels of Windows Error Reporting to always override any other consent policy setting.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting\\Consent\\

Value Name:  DefaultOverrideBehavior

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> Consent -> "Ignore custom consent settings" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-58401r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57479'
  tag rid: 'SV-71973r1_rule'
  tag stig_id: 'WINER-000018'
  tag gtitle: 'WINER-000018'
  tag fix_id: 'F-62769r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
