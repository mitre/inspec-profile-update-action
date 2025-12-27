control 'SV-108047' do
  title 'Google Android 10 must be configured to disable developer modes.'
  desc 'Developer modes expose features of the Google Android device that are not available during standard operation. An adversary may leverage a vulnerability inherent in a developer mode to compromise the confidentiality, integrity, and availability of DoD sensitive information. Disabling developer modes mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #26'
  desc 'check', 'Review Google Android device configuration settings to determine whether a developer mode is enabled.

This validation procedure is performed on both the MDM Administration Console and the Android 10 device. 

On the MDM console, do the following:

1. Open restrictions section.
2. Open Restrictions section.
3. Toggle "Disallow debugging Features" to on.

On the Android 10 device, do the following:

1. Go to Settings >> System.
2. Ensure Developer Options is not listed.

If the MDM console device policy is not set to disable developer mode or on the Android 10 device, the device policy is not set to disable developer mode, this is a finding.'
  desc 'fix', 'Configure the Google Android device to disable developer modes.

On the MDM Console:
1. Open restrictions section.
2. Open Restrictions section.
3. Toggle "Disallow debugging Features" to on.'
  impact 0.5
  ref 'DPMS Target Google Android 10.x'
  tag check_id: 'C-97783r1_chk'
  tag severity: 'medium'
  tag gid: 'V-98943'
  tag rid: 'SV-108047r1_rule'
  tag stig_id: 'GOOG-10-002800'
  tag gtitle: 'PP-MDF-301170'
  tag fix_id: 'F-104619r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
