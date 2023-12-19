control 'SV-230103' do
  title 'Motorola Android Pie must be provisioned as a fully managed device and configured to create a work profile.'
  desc 'The Android Enterprise Work Profile is the designated application group for the COPE use case.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify that Motorola Android Pie is configured as Corporate Owned Work Managed.
 
This procedure is performed on both the MDM Administrator console and the Motorola Android Pie device. 
 
On the MDM console, verify that the default enrollment is set to Corporate Owned Work Managed.
 
On the Android Pie device: 
1. Go to the application drawer.
2. Verify the presence of a Personal tab and a Work tab.

If on the MDM console the default enrollment is not set to Corporate Owned Work Managed or On the Android Pie device the user does not see a Work tab, this is a finding.'
  desc 'fix', 'Configure Motorola Android Pie in a Corporate Owned Work Managed configuration.

On the MDM console, configure the default enrollment as Corporate Owned Work Managed.

Refer to the MDM documentation to determine how to configure the device to enroll as Corporate Owned Work Managed.'
  impact 0.5
  ref 'DPMS Target Motorola Android 9.x COPE STIG'
  tag check_id: 'C-32418r538305_chk'
  tag severity: 'medium'
  tag gid: 'V-230103'
  tag rid: 'SV-230103r569708_rule'
  tag stig_id: 'MOTO-09-009600'
  tag gtitle: 'GOOG-09-009600'
  tag fix_id: 'F-32396r538306_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
