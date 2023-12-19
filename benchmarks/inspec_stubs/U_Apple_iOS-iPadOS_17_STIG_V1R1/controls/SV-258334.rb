control 'SV-258334' do
  title 'Apple iPadOS 17 must be configured to disable multiuser modes.'
  desc 'Multiuser mode allows multiple users to share a mobile device by providing a degree of separation between user data. To date, no mobile device with multiuser mode features meets DOD requirements for access control, data separation, and nonrepudiation for user accounts. In addition, the MDFPP does not include design requirements for multiuser account services. Disabling multiuser mode mitigates the risk of not meeting DOD multiuser account security policies.

SFR ID: FMT_SMF_EXT.1.1 #47a'
  desc 'check', 'Verify multiuser mode (shared iPad) is disabled in the MDM console for iPadOS devices. This requirement is not applicable for iOS devices.

If multiuser mode is not disabled in the MDM console for iPadOS devices, this is a finding.'
  desc 'fix', 'Disable multiuser mode (shared iPad) in the MDM console for iPadOS devices.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62075r927683_chk'
  tag severity: 'medium'
  tag gid: 'V-258334'
  tag rid: 'SV-258334r927685_rule'
  tag stig_id: 'AIOS-17-009800'
  tag gtitle: 'PP-MDF-333290'
  tag fix_id: 'F-61999r927684_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002110']
  tag nist: ['CM-6 b', 'AC-2 a']
end
