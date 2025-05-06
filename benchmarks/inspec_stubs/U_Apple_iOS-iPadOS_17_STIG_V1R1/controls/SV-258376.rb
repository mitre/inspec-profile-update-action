control 'SV-258376' do
  title 'Apple iOS/iPadOS 17 must be configured to disable "Auto Unlock" of the iPhone by an Apple Watch.'
  desc 'Auto Unlock allows an Apple Watch to automatically unlock an iPhone or Mac when in close proximity (not available for iPad). This feature allows the iPhone/Mac to be unlocked without the user entering the device passcode, which may lead to unauthorized users access to the iPhone/Mac and sensitive DOD data. This control is not applicable if the authorizing official (AO) has approved the use of Apple Watches.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', 'Determine if the site AO has approved the use of Apple Watch with DOD-owned iPhones. Look for a document showing approval. If not approved, review configuration settings to confirm "Allow Auto Unlock" is disabled. If approved, this requirement is not applicable.

This check procedure is performed on the device management tool.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS management tool, verify "Allow auto unlock" is not checked.

If Allow auto unlock is enabled, this is a finding.

This requirement will become "Supervised only" in a future iOS/iPadOS release.'
  desc 'fix', 'If the AO has not approved the use of Apple Watch with DOD-owned iPhones, configure the Apple iOS configuration profile to disable "Allow auto unlock".

The procedure for implementing this control will vary depending on the MDM/EMM used by the mobile service provider.

In the MDM console, set "Allow auto unlock" to "False".

This requirement will become "Supervised only" in a future iOS/iPadOS release.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62117r927809_chk'
  tag severity: 'medium'
  tag gid: 'V-258376'
  tag rid: 'SV-258376r927811_rule'
  tag stig_id: 'AIOS-17-014800'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62041r927810_fix'
  tag 'documentable'
  tag cci: ['CCI-000767', 'CCI-002235']
  tag nist: ['IA-2 (3)', 'AC-6 (10)']
end
