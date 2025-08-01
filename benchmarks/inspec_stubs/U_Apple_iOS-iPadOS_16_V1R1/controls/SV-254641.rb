control 'SV-254641' do
  title 'Apple iOS/iPadOS 16 must be configured to disable Auto Unlock of the iPhone by an Apple Watch.'
  desc 'Auto Unlock allows an Apple Watch to automatically unlock an iPhone or Mac when in close proximity (not available for iPad). This feature allows the iPhone/Mac to be unlocked without the user entering the device passcode, which may lead to unauthorized users access to the iPhone/Mac and sensitive DoD data. This control is not applicable if the authorizing official (AO) has approved the use of Apple Watches.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', 'Determine if the site AO has approved the use of Apple Watch with DoD-owned iPhones. Look for a document showing approval. If not approved, review configuration settings to confirm "Allow Auto Unlock" is disabled. If approved, this requirement is not applicable.

This check procedure is performed on the device management tool.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS management tool, verify "Allow auto unlock" is not checked.

If Allow auto unlock is enabled, this is a finding.'
  desc 'fix', 'If the AO has not approved the use of Apple Watch with DoD-owned iPhones, configure the Apple iOS configuration profile to disable "Allow auto unlock".

The procedure for implementing this control will vary depending on the MDM/EMM used by the mobile service provider.

In the MDM console, set "Allow auto unlock" to "False".'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16'
  tag check_id: 'C-58252r862177_chk'
  tag severity: 'medium'
  tag gid: 'V-254641'
  tag rid: 'SV-254641r862236_rule'
  tag stig_id: 'AIOS-16-014800'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-58198r862235_fix'
  tag 'documentable'
  tag cci: ['CCI-000767', 'CCI-002235']
  tag nist: ['IA-2 (3)', 'AC-6 (10)']
end
