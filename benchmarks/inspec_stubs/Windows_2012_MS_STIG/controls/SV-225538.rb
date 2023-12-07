control 'SV-225538' do
  title 'The Windows Help Experience Improvement Program must be disabled.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting ensures the Windows Help Experience Improvement Program is disabled to prevent information from being passed to the vendor.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \\Software\\Policies\\Microsoft\\Assistance\\Client\\1.0\\

Value Name: NoImplicitFeedback

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication Settings -> "Turn off Help Experience Improvement Program" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27237r471956_chk'
  tag severity: 'medium'
  tag gid: 'V-225538'
  tag rid: 'SV-225538r569185_rule'
  tag stig_id: 'WN12-UC-000007'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27225r471957_fix'
  tag 'documentable'
  tag legacy: ['SV-53144', 'V-16021']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
