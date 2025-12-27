control 'SV-106431' do
  title 'The Google Android Pie must be configured to disable developer modes.'
  desc 'Developer modes expose features of the Google Android device that are not available during standard operation. An adversary may leverage a vulnerability inherent in a developer mode to compromise the confidentiality, integrity, and availability of DoD sensitive information. Disabling developer modes mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #26'
  desc 'check', 'Review Google Android device configuration settings to determine whether a developer mode is enabled.

This validation procedure is performed on both the MDM Administration Console and the Android Pie device. 

On the MDM console, do the following:

1. Open restrictions section.
2. Open Restrictions section.
3. Confirm that "Debugging Features" is set to Disallow.

On the Android Pie device, do the following:

1. Go to Settings >> System
2. Ensure Developer Options is not listed.

If the MDM console device policy is not set to disable developer mode or on the Android Pie device, the device policy is not set to disable developer mode, this is a finding.'
  desc 'fix', 'Configure the Google Android device to disable developer modes.

On the MDM Console:
1. Open restrictions section.
2. Open Restrictions section.
3. Set "Debugging Features" to Disallow.'
  impact 0.5
  ref 'DPMS Target Google Android 9.x'
  tag check_id: 'C-96163r1_chk'
  tag severity: 'medium'
  tag gid: 'V-97327'
  tag rid: 'SV-106431r1_rule'
  tag stig_id: 'GOOG-09-002800'
  tag gtitle: 'PP-MDF-301170'
  tag fix_id: 'F-103007r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
