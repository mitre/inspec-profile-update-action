control 'SV-235087' do
  title 'Honeywell Mobility Edge Android Pie devices must be provisioned as a fully managed device and configured to create a work profile.'
  desc 'The Android Enterprise Work Profile is the designated application group for the COPE use case.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review that Honeywell Mobility Edge Android Pie devices is configured as Corporate Owned Work Managed.
 
This procedure is performed on both the MDM Administrator console and the Honeywell Mobility Edge Android Pie devices device. 
 
On the MDM console, verify that the default enrollment is set to Corporate Owned Work Managed.
 
On the Honeywell Android Pie device: 
1. Go to the application drawer.
2. Ensure there is a Personal tab and a Work tab.

If on the MDM console the default enrollment is set to Corporate Owned Work Managed or on the Honeywell Android Pie device the user does not see a Work tab, this is a finding.'
  desc 'fix', 'Configure Honeywell Android Pie devices in a Corporate Owned Work Managed configuration.

On the MDM console, configure the default enrollment as Corporate Owned Work Managed.

Refer to the MDM documentation to determine how to configure the device to enroll as Corporate Owned Work Managed.'
  impact 0.5
  ref 'DPMS Target Honeywell Android 9.x COPE'
  tag check_id: 'C-38306r623276_chk'
  tag severity: 'medium'
  tag gid: 'V-235087'
  tag rid: 'SV-235087r626527_rule'
  tag stig_id: 'HONW-09-009600'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-38269r623277_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
