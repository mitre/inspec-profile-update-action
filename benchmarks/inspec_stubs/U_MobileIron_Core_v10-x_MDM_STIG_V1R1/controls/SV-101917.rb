control 'SV-101917' do
  title 'The MobileIron Core v10 server must be configured with a periodicity for reachable events of six hours or less for the following commands to the agent: - query connectivity status; - query the current version of the MD firmware/software; - query the current version of the hardware model of the device; - query the current version of installed mobile applications; - read audit logs kept by the MD.'
  desc 'Key security-related status attributes must be queried frequently so the MobileIron Core v10 server can report status of devices under management to the administrator and management. The periodicity of these queries must be configured to an acceptable timeframe. Six hours or less is considered acceptable for normal operations.

SFR ID: FMT_SMF.1.1(2) e'
  desc 'check', 'Review the MDM server configuration settings.

Verify the server is configured with a periodicity for reachable events of "six hours or less" for the following commands to the agent: 
- query connectivity status;
- query the current version of the MD firmware/software;
- query the current version of the hardware model of the device;
- query the current version of installed mobile applications;
- read audit logs kept by the MD.

Verify the sync interval for a device:
1. In the Admin Portal, go to Policies & Config >> Policies.
2. Select the default sync policy.
3. Verify that the Sync Interval is set to "360 minutes or less".

If the "Sync interval" is not set up to "360 minutes or less", this is a finding.'
  desc 'fix', 'Configure the MDM server with a periodicity for reachable events of "six hours or less" for the following commands to the agent: 
- query connectivity status;
- query the current version of the MD firmware/software;
- query the current version of the hardware model of the device;
- query the current version of installed mobile applications;
-read audit logs kept by the MD.

Configure the "sync interval" for a device.
To configure the frequency for starting the synchronization process between a device and MobileIron Core:
1. In the Admin Portal, go to Policies & Config >> Policies.
2. Select the default sync policy.
3. Set "Sync Interval" to the number of minutes between synchronizations to be "360 minutes or less".
4. Click "Save".'
  impact 0.5
  ref 'DPMS Target MobileIron Core 10.x MDM'
  tag check_id: 'C-90973r1_chk'
  tag severity: 'medium'
  tag gid: 'V-91815'
  tag rid: 'SV-101917r1_rule'
  tag stig_id: 'MICR-10-000570'
  tag gtitle: 'PP-MDM-311057'
  tag fix_id: 'F-98017r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
