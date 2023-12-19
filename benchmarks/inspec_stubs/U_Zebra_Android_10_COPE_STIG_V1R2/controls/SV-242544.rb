control 'SV-242544' do
  title 'Zebra Android 10 must be configured to disable developer modes.'
  desc 'Developer modes expose features of the Zebra Android 10 device that are not available during standard operation. An adversary may leverage a vulnerability inherent in a developer mode to compromise the confidentiality, integrity, and availability of DoD sensitive information. Disabling developer modes mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #26'
  desc 'check', 'Review Zebra Android 10 device configuration settings to determine whether a developer mode is enabled.

This validation procedure is performed on both the MDM Administration Console and the Android 10 device. 

On the MDM console:
1. Open Restrictions section.
2. Toggle "Disallow Debugging Features" to On.

On the Zebra Android 10 device:
1. Go to Settings >> System.
2. Verify "Developer Options" is not listed.

If the MDM console device policy is not set to disable developer mode or on the Android 10 device, the device policy is not set to disable developer mode, this is a finding.'
  desc 'fix', 'Configure the Zebra Android 10 device to disable developer modes.

On the MDM console:
1. Open Restrictions section.
2. Toggle "Disallow Debugging Features" to On.'
  impact 0.5
  ref 'DPMS Target Zebra Android 10 COPE'
  tag check_id: 'C-45819r714475_chk'
  tag severity: 'medium'
  tag gid: 'V-242544'
  tag rid: 'SV-242544r714477_rule'
  tag stig_id: 'ZEBR-10-002800'
  tag gtitle: 'PP-MDF-301170'
  tag fix_id: 'F-45776r714476_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
