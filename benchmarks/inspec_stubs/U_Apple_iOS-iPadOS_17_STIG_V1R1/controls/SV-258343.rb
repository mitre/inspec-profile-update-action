control 'SV-258343' do
  title 'Apple iOS/iPadOS 17 must implement the management setting: not allow use of iPhone widgets on Mac.'
  desc "iPhone widgets on Mac use Handoff. Handoff permits a user of an iPhone and iPad to transition user activities from one device to another. Handoff passes sufficient information between the devices to describe the activity, but app data synchronization associated with the activity is handled though iCloud, which should be disabled on a compliant iPhone and iPad. If a user associates both DOD and personal devices to the same Apple ID, the user may improperly reveal information about the nature of the user's activities on an unprotected device. Disabling Handoff mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review configuration settings to confirm "Allow iPhone Widget on Mac" is disabled.

This a supervised-only control. If the iPhone or iPad being reviewed is not supervised by the MDM, this control is automatically a finding. 

This check procedure is performed only on the Apple iOS/iPadOS management tool.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "iPhone Widget on Mac" is unchecked.

If "Allow iPhone Widget on Mac" is checked in the Apple iOS/iPadOS management tool, this is a finding.'
  desc 'fix', 'Install a configuration profile to disable the installation of iPhone widgets on Mac. This a supervised-only control.'
  impact 0.3
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62084r927710_chk'
  tag severity: 'low'
  tag gid: 'V-258343'
  tag rid: 'SV-258343r927712_rule'
  tag stig_id: 'AIOS-17-010850'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62008r927711_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-7 a']
end
