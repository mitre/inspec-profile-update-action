control 'SV-258701' do
  title 'The Samsung Android device must be configured to perform the following management function: Disable Phone Hub.'
  desc 'It may be possible to transfer work profile data on a DOD Android device to an unauthorized Chromebook if the user has the same Google Account set up on the Chromebook. This may result in the exposure of sensitive DOD data.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', 'Review the management tool to confirm Phone Hub has been disabled.

On the management tool:
1. Open "Nearby notification streaming policy".
2. Verify "Nearby notification streaming policy" is set to "Disabled".
3. Open "Nearby app streaming policy".
4. Verify "Nearby app streaming policy" is set to "Disabled".
 
If on the management tool the "Nearby Streaming Policy" is not set to "Disabled", this is a finding.

Note: From a Chromebook, if a device is connected to the Phone Hub, try to set up the Notifications. It will fail to connect to the device to complete the setup if Phone Hub has been disabled on the DOD Android device.'
  desc 'fix', 'Configure the Samsung Android 14 device to disable the nearby notification and app streaming policy to disable Phone Hub.

On the management tool:
1. Open "Nearby notification streaming policy".
2. Set "Nearby notification streaming policy" to "Disabled".
3. Open "Nearby app streaming policy".
4. Set "Nearby app streaming policy" to "Disabled".'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 14 with Knox 3.x COPE'
  tag check_id: 'C-62441r931301_chk'
  tag severity: 'low'
  tag gid: 'V-258701'
  tag rid: 'SV-258701r931303_rule'
  tag stig_id: 'KNOX-14-225090'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62350r931302_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
