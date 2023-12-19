control 'SV-202136' do
  title 'The network device must be configured to to conduct backups of system level information contained in the information system when changes occur.'
  desc 'System-level information includes default and customized settings and security attributes, including ACLs that relate to the network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial of service condition is possible for all who utilize this critical network component.

This control requires the network device to support the organizational central backup process for system-level information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'Review the network device configuration to determine if the device is configured to conduct backups of system-level information contained in the information system when changes occur. 

If the network device is not configured to conduct backups of system-level data when changes occur, this is a finding.'
  desc 'fix', 'Configure the network device to conduct backups of system-level information contained in the information system when changes occur.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2262r382073_chk'
  tag severity: 'medium'
  tag gid: 'V-202136'
  tag rid: 'SV-202136r401224_rule'
  tag stig_id: 'SRG-APP-000516-NDM-000340'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-2263r382074_fix'
  tag 'documentable'
  tag legacy: ['SV-69553', 'V-55307']
  tag cci: ['CCI-000366', 'CCI-000537']
  tag nist: ['CM-6 b', 'CP-9 (b)']
end
