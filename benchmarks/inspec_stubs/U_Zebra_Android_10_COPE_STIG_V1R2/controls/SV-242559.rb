control 'SV-242559' do
  title 'Zebra Android 10 must be provisioned as a fully managed device and configured to create a Work Profile.'
  desc 'The Android Enterprise Work Profile is the designated application group for the COPE use case.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify that Zebra Android 10 is configured as Corporate Owned Work Managed.
 
This procedure is performed on both the MDM Administrator Console and the Zebra Android 10 device. 
 
On the MDM console, verify that the default enrollment is set to Corporate Owned Work Managed.
 
On the Zebra Android 10 device: 
1. Go to the application drawer.
2. Verify a Personal tab and a Work tab are present.

If on the MDM console the default enrollment is not set to Corporate Owned Work Managed or on the Zebra Android 10 device the user does not see a Work tab, this is a finding.'
  desc 'fix', 'Configure Zebra Android 10 as Corporate Owned Work Managed.

On the MDM console, configure the default enrollment as Corporate Owned Work Managed.

Refer to the MDM documentation to determine how to configure the device to enroll as Corporate Owned Work Managed.'
  impact 0.5
  ref 'DPMS Target Zebra Android 10 COPE'
  tag check_id: 'C-45834r714520_chk'
  tag severity: 'medium'
  tag gid: 'V-242559'
  tag rid: 'SV-242559r714522_rule'
  tag stig_id: 'ZEBR-10-009600'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-45791r714521_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
