control 'SV-246944' do
  title 'ONTAP must be configured to conduct backups of system level information.'
  desc 'System-level information includes default and customized settings and security attributes, including ACLs that relate to the network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial of service condition is possible for all who utilize this critical network component.

This control requires the network device to support the organizational central backup process for system-level information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'Use "set -privilege advanced" reply "y" to continue and "system configuration backup settings show" to see if ONTAP is configured for system backups.

If the ONTAP is not configured to conduct backups of system-level data when changes occur, this is a finding.'
  desc 'fix', 'Configure ONTAP to conduct backups of system level information with "set -privilege advanced" reply "y" to continue and "system configuration backup create -node <node_name> -backup-type cluster -backup-name <name>".'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50376r769162_chk'
  tag severity: 'medium'
  tag gid: 'V-246944'
  tag rid: 'SV-246944r769164_rule'
  tag stig_id: 'NAOT-CM-000007'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag fix_id: 'F-50330r769163_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000537']
  tag nist: ['CM-6 b', 'CP-9 (b)']
end
