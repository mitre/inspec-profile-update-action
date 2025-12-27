control 'SV-225466' do
  title 'The Windows dialog box title for the legal banner must be configured.'
  desc 'Failure to display the logon banner prior to a logon attempt will negate legal proceedings resulting from unauthorized access to system resources.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: LegalNoticeCaption

Value Type: REG_SZ
Value: See message title options below

"DoD Notice and Consent Banner", "US Department of Defense Warning Statement", or a site-defined equivalent. 

If a site-defined title is used, it can in no case contravene or modify the language of the banner text required in V-1089.

Automated tools may only search for the titles defined above. If a site-defined title is used, a manual review will be required.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive Logon: Message title for users attempting to log on" to "DoD Notice and Consent Banner", "US Department of Defense Warning Statement", or a site-defined equivalent. 

If a site-defined title is used, it can in no case contravene or modify the language of the banner text required in V-1089.'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27165r471740_chk'
  tag severity: 'low'
  tag gid: 'V-225466'
  tag rid: 'SV-225466r569185_rule'
  tag stig_id: 'WN12-SO-000023'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag fix_id: 'F-27153r471741_fix'
  tag 'documentable'
  tag legacy: ['V-26359', 'SV-53121']
  tag cci: ['CCI-000048', 'CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 a', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3']
end
