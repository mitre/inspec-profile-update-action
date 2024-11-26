control 'SV-230088' do
  title 'The Motorola Android Pie must be configured to disable developer modes.'
  desc 'Developer modes expose features of the Motorola Android device that are not available during standard operation. An adversary may leverage a vulnerability inherent in a developer mode to compromise the confidentiality, integrity, and availability of DoD sensitive information. Disabling developer modes mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #26'
  desc 'check', 'Review Motorola Android device configuration settings to determine whether a developer mode is enabled.

This validation procedure is performed on both the MDM Administration Console and the Android Pie device. 

On the MDM console: 
1. Open Restrictions section.
2. Verify "Debugging Features" is set to "Disallow".

On the Android Pie device: 
1. Go to Settings >> System.
2. Verify "Developer Options" is not listed.

If the MDM console device policy is not set to disable developer mode, or on the Android Pie device, the device policy is not set to disable developer mode, this is a finding.'
  desc 'fix', 'Configure the Motorola Android device to disable developer modes.

On the MDM console: 
1. Open Restrictions section.
2. Set "Debugging Features" to "Disallow".'
  impact 0.5
  ref 'DPMS Target Motorola Android 9.x COPE STIG'
  tag check_id: 'C-32403r538260_chk'
  tag severity: 'medium'
  tag gid: 'V-230088'
  tag rid: 'SV-230088r569708_rule'
  tag stig_id: 'MOTO-09-002800'
  tag gtitle: 'GOOG-09-002800'
  tag fix_id: 'F-32381r538261_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
