control 'SV-258407' do
  title 'Google Android 14 must allow only the administrator (MDM) to perform the following management function: Disable Phone Hub.'
  desc 'It may be possible to transfer work profile data on a DOD Android device to an unauthorized Chromebook if the user has the same Google Account set up on the Chromebook and in the work profile on the Android device. This may result in the exposure of sensitive DOD data.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', 'Review the EMM configuration to confirm phone hub has been disabled.

On the management tool:
1. Open "Nearby notification streaming policy".
2. Verify "Nearby notification streaming policy" is set to "Disabled".
3. Open "Nearby app streaming policy".
4. Verify "Nearby app streaming policy" is set to "Disabled".

If on the management tool the "Nearby Streaming Policy" is not set to "Disabled" and  "Nearby app streaming policy" is not set to "Disabled", this is a finding.

Note: From a Chromebook, if a device is connected to the Phone Hub, try to set up the Notifications and it will fail to connect to the device to complete the set up if phone hub has been disabled on the DOD Android device.'
  desc 'fix', 'Configure Google Android 14 device to disable the nearby notification streaming policy to disable Phone Hub.

COPE and COBO:

On the EMM console:
1. Open "Nearby notification streaming policy".
2. Set "Nearby notification streaming policy" to "Disabled".
3. Open "Nearby app streaming policy".
4. Set "Nearby app streaming policy" to "Disabled".'
  impact 0.3
  ref 'DPMS Target Google Android 14 COBO'
  tag check_id: 'C-62148r928244_chk'
  tag severity: 'low'
  tag gid: 'V-258407'
  tag rid: 'SV-258407r928246_rule'
  tag stig_id: 'GOOG-14-012400'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62072r928245_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
