control 'SV-71881' do
  title 'The system must be configured to send error reports on TCP port 1232.'
  desc "An error reporting site's TCP port must be defined in the local system in order to forward data from local systems via TCP.  Port 1232 is the recommended port setting."
  desc 'check', 'This requirement is NA if Windows Error Reporting is not configured to forward reports to a collection server (see V-57457).

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting\\

Value Name:  CorporateWerPortNumber

Type:  REG_DWORD
Value:  0x000004d0 (1232)'
  desc 'fix', 'This requirement is NA if Windows Error Reporting is not configured to forward reports to a collection server (see V-57457).

Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> Advanced Error Reporting Settings -> "Configure Corporate Windows Error Reporting" to "Enabled" with "1232" defined as the "Server Port".'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-58311r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57461'
  tag rid: 'SV-71881r1_rule'
  tag stig_id: 'WINER-000009'
  tag gtitle: 'WINER-000009'
  tag fix_id: 'F-62671r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
