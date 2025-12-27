control 'SV-226165' do
  title 'The Internet File Association service must be turned off.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents unhandled file associations from using the Microsoft Web service to find an application.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

Value Name: NoInternetOpenWith

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off Internet File Association service" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27867r475818_chk'
  tag severity: 'medium'
  tag gid: 'V-226165'
  tag rid: 'SV-226165r794427_rule'
  tag stig_id: 'WN12-CC-000038'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27855r475819_fix'
  tag 'documentable'
  tag legacy: ['V-15674', 'SV-53021']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
