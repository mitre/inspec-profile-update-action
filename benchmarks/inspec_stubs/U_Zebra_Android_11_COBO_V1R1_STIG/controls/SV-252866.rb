control 'SV-252866' do
  title 'Zebra Android 11 must be configured to disable multi-user modes.'
  desc 'Multi-user mode allows multiple users to share a mobile device by providing a degree of separation between user data. To date, no mobile device with multi-user mode features meets DoD requirements for access control, data separation, and non-repudiation for user accounts. In addition, the MDFPP does not include design requirements for multi-user account services. Disabling multi-user mode mitigates the risk of not meeting DoD multi-user account security policies.

SFR ID: FMT_SMF_EXT.1.1 #47b'
  desc 'check', 'Review documentation on the Zebra Android device and inspect the configuration on the Zebra Android device to disable multi-user modes.

This validation procedure is performed on both the EMM Administration Console and the Android 11 device. 

On the EMM console, do the following:
1. Open "Set user restrictions".
2. Verify that "Disallow modify accounts" is toggled to "On".

On the Android 11 device, do the following:
1. Go to Settings >> Accounts>> Work.
2. Validate that "Add Account" is grayed out.

If the EMM console device policy is not set to disable multi-user modes or on the Android 11 device, the device policy is not set to disable multi-user modes, this is a finding.'
  desc 'fix', 'Configure the Zebra Android 11 device to disable multi-user modes.

On the EMM console:
1. Open "Set user restrictions".
2. Toggle "Disallow modify accounts" to "On".'
  impact 0.5
  ref 'DPMS Target Zebra Android 11 COBO'
  tag check_id: 'C-56322r820523_chk'
  tag severity: 'medium'
  tag gid: 'V-252866'
  tag rid: 'SV-252866r820525_rule'
  tag stig_id: 'ZEBR-11-004700'
  tag gtitle: 'PP-MDF-301280'
  tag fix_id: 'F-56272r820524_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002080']
  tag nist: ['CM-6 b', 'CA-3 (5)']
end
