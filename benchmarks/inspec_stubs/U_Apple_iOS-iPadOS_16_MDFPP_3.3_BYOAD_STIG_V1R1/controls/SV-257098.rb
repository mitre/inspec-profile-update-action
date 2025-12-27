control 'SV-257098' do
  title 'The iOS/iPadOS 16 BYOAD device must be configured to disable copy and paste from managed (work profile) apps/contacts to unmanaged (personal profile) apps/contacts and vice versa.'
  desc 'Protection of DOD data is a key construct of the BYOAD security baseline, including disabling the capability to copy/paste data between the managed/work profile and the unmanaged/personal profile.

Reference: NIST Special Publication 1800-22, "Mobile Device Security: Bring Your Own Device (BYOD)".

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.
 
In the iOS management tool, verify "Require managed pasteboard" is set to "True".

If "Require managed pasteboard" is not set to "True", this is a finding.

Note: This requirement is the same as AIOS-16-714600 in the Apple iOS/iPadOS 16 BYOAD STIG.'
  desc 'fix', 'Configure the Apple iOS configuration profile to disable copy/paste of data from managed to unmanaged applications.

The procedure for implementing this control will vary depending on the MDM/EMM used by the mobile service provider.

In the MDM console, set "Require managed pasteboard" to "True".

Note: This requirement is the same as AIOS-16-714600 in the Apple iOS/iPadOS 16 BYOAD STIG.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16 MDFPP 3.3 BYOAD'
  tag check_id: 'C-60783r904037_chk'
  tag severity: 'medium'
  tag gid: 'V-257098'
  tag rid: 'SV-257098r904039_rule'
  tag stig_id: 'AIOS-16-800160'
  tag gtitle: 'PP-BYO-000160'
  tag fix_id: 'F-60724r904038_fix'
  tag 'documentable'
  tag cci: ['CCI-002218']
  tag nist: ['AC-4 (22)']
end
