control 'SV-250943' do
  title 'Apple iOS/iPadOS 15 must be configured to disable multiuser modes.'
  desc 'Multiuser mode allows multiple users to share a mobile device by providing a degree of separation between user data. To date, no mobile device with multiuser mode features meets DoD requirements for access control, data separation, and nonrepudiation for user accounts. In addition, the MDFPP does not include design requirements for multiuser account services. Disabling multiuser mode mitigates the risk of not meeting DoD multiuser account security policies.

SFR ID: FMT_SMF_EXT.1.1 #47a'
  desc 'check', 'Verify multiuser mode is disabled in the MDM console for iPadOS devices.

If multiuser mode is not disabled in the MDM console for iPadOS devices, this is a finding.'
  desc 'fix', 'Disable multiuser mode in the MDM console for iPadOS devices.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 15'
  tag check_id: 'C-54378r801918_chk'
  tag severity: 'medium'
  tag gid: 'V-250943'
  tag rid: 'SV-250943r801920_rule'
  tag stig_id: 'AIOS-15-009800'
  tag gtitle: 'PP-MDF-323290'
  tag fix_id: 'F-54332r801919_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002110']
  tag nist: ['CM-6 b', 'AC-2 a']
end
