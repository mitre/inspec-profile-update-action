control 'SV-96907' do
  title 'The MaaS360 MDM Agent must be configured to implement the management setting: periodicity of reachability events equals six hours or less.'
  desc 'Key security-related status attributes must be queried frequently so the MaaS360 MDM Agent can report status of devices under management to the Administrator and management. The periodicity of these queries must be configured to an acceptable timeframe. Six hours or less is considered acceptable for normal operations.

SFR ID: FAU_ALT_EXT.2.1'
  desc 'check', 'Verify the periodicity for agent checking to the server has been set to six hours or less.

For Apple iOS devices, confirm with IBM that the periodicity for agent checking to the server has been set to 6 hours or less.

For Samsung Android devices:
1. In the portal, navigate to "Security".
2. Select "Policy".
3. Select the policy for Samsung Android devices.
4. Open the policy.
5. Select "Device Settings" and then "Device Management".
6. Verify "Data Heartbeat Frequency" is set to 360 minutes or less.

If the periodicity for agent checking to the server has not been set to 6 hours or less, this is a finding.'
  desc 'fix', 'The procedure for configuring the periodicity depends on the MOS type.

For Apple iOS devices, the site System Administrator should ask IBM to configure the SaaS to set the periodicity for agent checking to the server to six hours or less.

For Samsung Android devices:
1. In the portal, navigate to "Security".
2. Select "Policy".
3. Select the policy for Samsung Android devices.
4. Open the policy.
5. Select "Device Settings" and then "Device Management".
6. Set the "Data Heartbeat Frequency" to 360 minutes or less.'
  impact 0.5
  ref 'DPMS Target IBM MaaS360 with Watson v10.x MDM'
  tag check_id: 'C-81995r1_chk'
  tag severity: 'medium'
  tag gid: 'V-82193'
  tag rid: 'SV-96907r1_rule'
  tag stig_id: 'M360-10-301700'
  tag gtitle: 'PP-MDM-301011'
  tag fix_id: 'F-89053r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
