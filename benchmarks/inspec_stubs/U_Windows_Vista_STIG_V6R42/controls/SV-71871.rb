control 'SV-71871' do
  title 'The system must be configured to use SSL to forward error reports.'
  desc 'The use of SSL enables the secure forwarding of error reporting data from local systems to a reporting site.'
  desc 'check', 'This requirement is NA if Windows Error Reporting is not configured to forward reports to a collection server (see V-57457).

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting\\

Value Name:  CorporateWerUseSSL

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'This requirement is NA if Windows Error Reporting is not configured to forward reports to a collection server (see V-57457).

Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> Advanced Error Reporting Settings -> "Configure Corporate Windows Error Reporting" to "Enabled" with "Connect using SSL" selected.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-58301r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57459'
  tag rid: 'SV-71871r1_rule'
  tag stig_id: 'WINER-000008'
  tag gtitle: 'WINER-000008'
  tag fix_id: 'F-62661r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end
