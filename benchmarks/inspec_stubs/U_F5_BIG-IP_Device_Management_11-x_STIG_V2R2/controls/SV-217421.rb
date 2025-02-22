control 'SV-217421' do
  title 'The BIG-IP appliance must create backups of system-level information contained in the information system when changes occur or weekly, whichever is sooner.'
  desc 'System-level information includes default and customized settings and security attributes, including ACLs that relate to the network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial of service condition is possible for all who utilize this critical network component.

This control requires the network device to support the organizational central backup process for system-level information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'Verify the BIG-IP appliance is capable of creating backups of system-level information contained in the information system when changes occur.

Navigate to the BIG-IP System manager >> System >> Archives.

Review the list of archives to verify backups are conducted in accordance with the local backup policy.

If the BIG-IP appliance does not support the creating backups of system-level information contained in the information system when changes occur or weekly, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to create backups of system-level information contained in the information system when changes occur or weekly, whichever is sooner.'
  impact 0.3
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18646r290817_chk'
  tag severity: 'low'
  tag gid: 'V-217421'
  tag rid: 'SV-217421r916221_rule'
  tag stig_id: 'F5BI-DM-000277'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag fix_id: 'F-18644r290818_fix'
  tag 'documentable'
  tag legacy: ['SV-74663', 'V-60233']
  tag cci: ['CCI-000366', 'CCI-000537']
  tag nist: ['CM-6 b', 'CP-9 (b)']
end
