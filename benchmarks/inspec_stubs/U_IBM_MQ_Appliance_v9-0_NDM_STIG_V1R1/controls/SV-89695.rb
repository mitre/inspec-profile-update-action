control 'SV-89695' do
  title 'The MQ Appliance network device must support organizational requirements to conduct backups of system level information contained in the information system when changes occur or weekly, whichever is sooner.'
  desc 'System-level information includes default and customized settings and security attributes, including ACLs that relate to the MQ Appliance network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial of service condition is possible for all who utilize this critical network component. 

This control requires the MQ Appliance network device to support the organizational central backup process for system-level information associated with the MQ Appliance network device. This function may be provided by the MQ Appliance network device itself; however, the preferred best practice is a centralized backup rather than each MQ Appliance network device performing discrete backups.'
  desc 'check', 'Interview the system admin and determine how the MQ system is backed up.

The MQ Appliance provides three features for providing system backup: 

- High Availability (HA) configuration of paired appliances 
https://ibm.biz/Bd43aV 
- Disaster Recovery (DR) configuration using a paired off-site appliance 
https://ibm.biz/Bd43au 
- Manual backup and restore 
https://ibm.biz/Bd43ah

If manual backup and restore is used verify backups are performed when changes to the system occur or at least weekly.

If none of the above methods are employed or if no backups exist, this is a finding.'
  desc 'fix', 'Configure the MQ appliance to use one of the following backup solutions.

- High Availability (HA) configuration of paired appliances
- Disaster Recovery (DR) configuration using a paired off-site appliance
- Manual backup and restore'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74873r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75021'
  tag rid: 'SV-89695r1_rule'
  tag stig_id: 'MQMH-ND-001490'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag fix_id: 'F-81635r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000537']
  tag nist: ['CM-6 b', 'CP-9 (b)']
end
