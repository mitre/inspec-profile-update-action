control 'SV-254799' do
  title 'Google Android 13 must allow only the Administrator (MDM) to perform the following management function: Disable Phone Hub.'
  desc 'It may be possible to transfer work profile data on a DOD Android device to an unauthorized ChromeBook if the user has the same Google Account set up on the ChromeBook and in the work profile on the Android device. This may result in the exposure of sensitive DOD data.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', 'Review the EMM configuration to confirm phone hub has been disabled.

On the EMM console:
1. Open "Set user restrictions".
2. Verify "Nearby notification streaming policy" is set to "NEARBY_STREAMING_DISABLED".
 
If on EMM console the "Nearby Streaming Policy" is not set to "NEARBY_STREAMING_DISABLED", this is a finding.

Note: From a Chromebook, if a device is connected to the Phone Hub, try to set up the Notifications and it will fail to connect to the device to complete the set up if phone hub has been disabled on the DOD Android device.'
  desc 'fix', 'Configure Google Android 13 device to disable the nearby notification streaming policy to disable Phone Hub.

COPE and COBO:

On the EMM console:
1. Open "Set user restrictions".
2. Toggle "Nearby Streaming Policy" to "NEARBY_STREAMING_DISABLED".'
  impact 0.3
  ref 'DPMS Target Google Android 13 COPE'
  tag check_id: 'C-58410r862777_chk'
  tag severity: 'low'
  tag gid: 'V-254799'
  tag rid: 'SV-254799r862779_rule'
  tag stig_id: 'GOOG-13-012400'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-58356r862778_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
