control 'SV-258361' do
  title 'Apple iOS/iPadOS 17 must implement the management setting: approved Apple Watches must be managed by an MDM.'
  desc 'Authorizing official (AO) approval is required before an Apple Watch (DOD owned or personally owned) can be paired with a DOD-owned iPhone to ensure the AO has evaluated the risk in having sensitive DOD data transferred to and stored on an Apple Watch in their operational environment.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Determine if the site AO has approved the use of Apple Watch with DOD-owned iPhones. Look for a document showing approval. If not approved, this requirement is not applicable.

If approved, verify on the MDM server that the Apple Watch is being managed by the MDM. Have the MDM system administrator show that the Apple Watch is being managed by the MDM.

If the AO has approved pairing an Apple Watch with a DOD-owned iPhone and the Apple Watch is not being managed by the site MDM server, this is a finding.

Note: The iPhone paired to the Apple Watch must be supervised for the MDM to manage the Apple Watch.'
  desc 'fix', 'If the AO has not approved the use of Apple Watch with DOD-owned iPhones, this requirement is not applicable. 

If the AO has approved the use of Apple Watch with DOD-owned iPhones, enroll the Apple Watch in MDM management.

Note: The iPhone paired to the Apple Watch must be supervised for the MDM to manage the Apple Watch.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62102r927764_chk'
  tag severity: 'medium'
  tag gid: 'V-258361'
  tag rid: 'SV-258361r927766_rule'
  tag stig_id: 'AIOS-17-012650'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62026r927765_fix'
  tag 'documentable'
  tag cci: ['CCI-000097', 'CCI-000366']
  tag nist: ['AC-20 (2)', 'CM-6 b']
end
