control 'SV-257096' do
  title "The EMM system supporting the iOS/iPadOS 16 BYOAD must be configured to only wipe managed data and apps and not unmanaged data and apps when the user's access is revoked or terminated, the user no longer has the need to access DOD data or IT, or the user reports a registered device as lost, stolen, or showing indicators of compromise."
  desc 'DOD policy requires the protection and privacy of personal data and activities to the maximum extent possible on BYOADs.

Reference: DOD policy "Use of Non-Government Mobile Devices". 3.b.(5).

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', "Verify the EMM system administrators supporting the iOS/iPadOS 16 BYOAD have been trained to only wipe managed data and apps when the user's access is revoked or terminated, the user no longer has the need to access DOD data or IT, or the user reports a registered device as lost, stolen, or showing indicators of compromise.

If the EMM system administrators supporting the iOS/iPadOS 16 BYOAD have not been trained to only wipe managed data and apps, this is a finding."
  desc 'fix', "Train EMM system administrators supporting the iOS/iPadOS 16 BYOAD to only wipe managed data and apps when the user's access is revoked or terminated, the user no longer has the need to access DOD data or IT, or the user reports a registered device as lost, stolen, or showing indicators of compromise."
  impact 0.3
  ref 'DPMS Target Apple iOS-iPadOS 16 MDFPP 3.3 BYOAD'
  tag check_id: 'C-60781r904031_chk'
  tag severity: 'low'
  tag gid: 'V-257096'
  tag rid: 'SV-257096r904033_rule'
  tag stig_id: 'AIOS-16-800130'
  tag gtitle: 'PP-BYO-000130'
  tag fix_id: 'F-60722r904032_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
