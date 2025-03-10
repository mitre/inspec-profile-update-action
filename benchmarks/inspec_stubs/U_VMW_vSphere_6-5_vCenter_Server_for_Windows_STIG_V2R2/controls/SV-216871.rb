control 'SV-216871' do
  title 'The vCenter Server for Windows must protect the confidentiality and integrity of transmitted information by isolating IP-based storage traffic.'
  desc 'Virtual machines might share virtual switches and VLANs with the IP-based storage configurations. IP-based storage includes vSAN, iSCSI, and NFS. This configuration might expose IP-based storage traffic to unauthorized virtual machine users. IP-based storage frequently is not encrypted. It can be viewed by anyone with access to this network. To restrict unauthorized users from viewing the IP-based storage traffic, the IP-based storage network must be logically separated from the production traffic. Configuring the IP-based storage adaptors on separate VLANs or network segments from other VMkernels and Virtual Machines will limit unauthorized users from viewing the traffic.'
  desc 'check', 'If IP-based storage is not used, this is not applicable.

IP-Based storage (iSCSI, NFS, vSAN) VMkernel port groups must be in a dedicated VLAN that can be on a common standard or distributed virtual switch that is logically separated from other traffic types. The check for this will be unique per environment. From the vSphere Client select the ESXi host and go to Configure >> Networking >> VMkernel adapters and review the VLANs associated with any IP-Based storage VMkernels and verify they are dedicated for that purpose and are logically separated from other functions.

If any IP-Based storage networks are not isolated from other traffic types, this is a finding.'
  desc 'fix', 'Configuration of an IP-Based VMkernel will be unique to each environment but for example to modify the IP address and VLAN information to the correct network on a standard switch for an iSCSI VMkernel do the following:

From the vSphere Web Client select the ESXi host and go to Configure >> Networking >> VMkernel adapters. Select the Storage VMkernel (for any IP-based storage) and click the pencil icon >> On the Port properties tab uncheck everything (unless vSAN). On the IP Settings tab >> Enter the appropriate IP address and subnet information and click OK. Set the appropriate VLAN ID >> Configure >> Networking >> Virtual switches. Select the Storage portgroup (ISCSI, NFS, vSAN) and click the pencil icon >> On the properties tab, enter the appropriate VLAN ID and click OK.'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18102r366327_chk'
  tag severity: 'medium'
  tag gid: 'V-216871'
  tag rid: 'SV-216871r612237_rule'
  tag stig_id: 'VCWN-65-000052'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18100r366328_fix'
  tag 'documentable'
  tag legacy: ['SV-104637', 'V-94807']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
