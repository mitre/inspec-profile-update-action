control 'SV-226364' do
  title 'Windows Help Ratings feedback must be turned off.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting ensures users cannot provide ratings feedback to Microsoft for Help content.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \\Software\\Policies\\Microsoft\\Assistance\\Client\\1.0\\

Value Name: NoExplicitFeedback

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication Settings -> "Turn off Help Ratings" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28066r476936_chk'
  tag severity: 'medium'
  tag gid: 'V-226364'
  tag rid: 'SV-226364r794639_rule'
  tag stig_id: 'WN12-UC-000008'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-28054r476937_fix'
  tag 'documentable'
  tag legacy: ['SV-53145', 'V-16048']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
