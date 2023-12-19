control 'SV-253375' do
  title 'Web publishing and online ordering wizards must be prevented from downloading a list of providers.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system. This setting prevents Windows from downloading a list of providers for the Web publishing and online ordering wizards.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

Value Name: NoWebServices

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Internet Communication Management >> Internet Communication settings >> "Turn off Internet download for Web publishing and online ordering wizards" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56828r829207_chk'
  tag severity: 'medium'
  tag gid: 'V-253375'
  tag rid: 'SV-253375r829209_rule'
  tag stig_id: 'WN11-CC-000105'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56778r829208_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
