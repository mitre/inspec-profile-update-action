control 'SV-251419' do
  title 'The Ivanti MobileIron Core server must be configured with the periodicity of the following commands to the agent of six hours or less: - query connectivity status - query the current version of the managed device firmware/software - query the current version of installed mobile applications - read audit logs kept by the managed device.'
  desc 'Without verification, security functions may not operate correctly and this failure may go unnoticed.

Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

This requirement applies to applications performing security functions and the applications performing security function verification/testing.

'
  desc 'check', 'Review the MDM server configuration settings and verify the server is configured with a periodicity for reachable events of six hours or less for the following commands to the agent: 
- query connectivity status;
- query the current version of the MD firmware/software;
- query the current version of the hardware model of the device;
- query the current version of installed mobile applications;
- read audit logs kept by the MD.

Verify the sync interval for a device:
1. In the Admin Portal, go to Policies & Config >> Policies.
2. Select the default sync policy.
3. Verify that the Sync Interval is set to 360 minutes or less.

If the Sync interval is not set to 360 minutes or less, this is a finding.'
  desc 'fix', 'Configure the MDM server with a periodicity for reachable events of six hours or less for the following commands to the agent: 
- query connectivity status;
- query the current version of the MD firmware/software;
- query the current version of the hardware model of the device;
- query the current version of installed mobile applications;
-read audit logs kept by the MD.

Configure the sync interval for a device:
To configure the frequency for starting the synchronization process between a device in MobileIron Core:
1. In the Admin Portal, go to Policies & Config >> Policies.
2. Select the default sync policy.
3. Set Sync Interval to the number of minutes between synchronizations to be 360 minutes or less.
4. Click "Save".'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Core MDM Server'
  tag check_id: 'C-54854r806387_chk'
  tag severity: 'medium'
  tag gid: 'V-251419'
  tag rid: 'SV-251419r806404_rule'
  tag stig_id: 'IMIC-11-010900'
  tag gtitle: 'SRG-APP-000472-UEM-000347'
  tag fix_id: 'F-54807r806388_fix'
  tag satisfies: ['FAU_NET_EXT.1.1', 'FMT_SMF.1.1(2) c.3 \nReference: PP-MDM-411057']
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
