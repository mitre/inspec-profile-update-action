control 'SV-217814' do
  title 'Samsung Android must be configured to disable multi-user modes.'
  desc 'Multi-user mode allows multiple users to share a mobile device by providing a degree of separation between user data. To date, no mobile device with multi-user mode features meets DoD requirements for access control, data separation, and non-repudiation for user accounts. In addition, the MDFPP does not include design requirements for multi-user account services. Disabling multi-user mode mitigates the risk of not meeting DoD multi-user account security policies.

SFR ID: FMT_SMF_EXT.1.1 #47b'
  desc 'check', 'Review configuration settings to confirm that multi-user mode has been disabled. 

This procedure is performed on both the MDM Administrator console and the Samsung Android device. 

On the MDM console, in Knox MultiUser, verify that "allow multi-user mode" is not selected. 

On the Samsung Android device, open Settings and verify that the "User" setting is not available. 

If on the MDM console "allow multi-user mode" is selected, or on the Samsung Android device the "User" setting is available, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disable multi-user modes. 

On the MDM console, in Knox MultiUser, unselect "allow multi-user mode".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COPE KPE Legacy'
  tag check_id: 'C-19030r362900_chk'
  tag severity: 'medium'
  tag gid: 'V-217814'
  tag rid: 'SV-217814r388482_rule'
  tag stig_id: 'KNOX-09-000645'
  tag gtitle: 'PP-MDF-301280'
  tag fix_id: 'F-19028r362901_fix'
  tag 'documentable'
  tag legacy: ['SV-103975', 'V-93889']
  tag cci: ['CCI-000366', 'CCI-002110']
  tag nist: ['CM-6 b', 'AC-2 a']
end
