control 'SV-48454' do
  title 'Handwriting personalization data sharing with Microsoft must be prevented.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents data from the handwriting recognition personalization tool being shared with Microsoft.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\TabletPC\\

Value Name: PreventHandwritingDataSharing

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off handwriting personalization data sharing" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45117r2_chk'
  tag severity: 'low'
  tag gid: 'V-21966'
  tag rid: 'SV-48454r2_rule'
  tag stig_id: 'WN08-CC-000034'
  tag gtitle: 'Handwriting personalization data sharing'
  tag fix_id: 'F-41581r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
