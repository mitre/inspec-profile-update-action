control 'SV-108077' do
  title 'Google Android 10 must be provisioned as a fully managed device and configured to create a work profile.'
  desc 'The Android Enterprise Work Profile is the designated application group for the COPE use case.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review that Google Android 10 is configured as Corporate Owned Work Managed.

This procedure is performed on both the MDM Administrator console and the Google Android 10 device. 

On the MDM console, verify that the default enrollment is set to Corporate Owned Work Managed.

On the Google Android 10 device, do the following: 
1. Go to the application drawer.
2. Ensure a Personal tab and a Work tab are present.

If on the MDM console the account the default enrollment is set to Corporate Owned Work Managed or on the Google Android 10 device the user does not see a Work tab, this is a finding.'
  desc 'fix', 'Configure Google Android 10 in a Corporate Owned Work Managed configuration.

On the MDM console, configure the default enrollment as Corporate Owned Work Managed.

Refer to the MDM documentation to determine how to configure the device to enroll as Corporate Owned Work Managed.'
  impact 0.5
  ref 'DPMS Target Google Android 10.x'
  tag check_id: 'C-97813r1_chk'
  tag severity: 'medium'
  tag gid: 'V-98973'
  tag rid: 'SV-108077r1_rule'
  tag stig_id: 'GOOG-10-009600'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-104649r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
