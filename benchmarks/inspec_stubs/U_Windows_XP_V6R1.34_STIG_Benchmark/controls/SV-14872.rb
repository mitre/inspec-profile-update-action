control 'SV-14872' do
  title 'Windows is prevented from using Windows Update to search for drivers.'
  desc 'This check verifies that the system is configured to prevent Windows from searching Windows Update for device drivers when no local drivers for a device are present.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication setting ‘Turn off Windows Update device driver searching’ to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-14261'
  tag rid: 'SV-14872r1_rule'
  tag gtitle: 'Windows Update Device Drive Searching'
  tag fix_id: 'F-13586r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCSL-1'
end
