control 'SV-235045' do
  title 'The Honeywell Mobility Edge Android Pie device must be configured to disable developer modes.'
  desc 'Developer modes expose features of the Honeywell Android device that are not available during standard operation. An adversary may leverage a vulnerability inherent in a developer mode to compromise the confidentiality, integrity, and availability of DoD sensitive information. Disabling developer modes mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #26'
  desc 'check', 'Review Honeywell Android device configuration settings to determine whether a developer mode is enabled.

This validation procedure is performed on both the MDM Administration console and the Android Pie device. 

On the MDM console:
1. Open Restrictions section.
2. Confirm that "Debugging Features" is set to "Disallow".

On the Honeywell Android Pie device:
1. Go to Settings >> System.
2. Ensure Developer Options is not listed.

If the MDM console device policy is not set to disable developer mode or on the Honeywell Android Pie device, the device policy is not set to disable developer mode, this is a finding.'
  desc 'fix', 'Configure the Honeywell Android device to disable developer modes.

On the MDM console:
1. Open Restrictions section.
2. Set "Debugging Features" to "Disallow".'
  impact 0.5
  ref 'DPMS Target Honeywell Android 9.x COBO'
  tag check_id: 'C-38233r623045_chk'
  tag severity: 'medium'
  tag gid: 'V-235045'
  tag rid: 'SV-235045r626530_rule'
  tag stig_id: 'HONW-09-002800'
  tag gtitle: 'PP-MDF-301170'
  tag fix_id: 'F-38196r623046_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
