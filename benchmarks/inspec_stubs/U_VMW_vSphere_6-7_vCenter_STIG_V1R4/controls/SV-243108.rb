control 'SV-243108' do
  title 'The vCenter Server must protect the confidentiality and integrity of transmitted information by isolating IP-based storage traffic.'
  desc 'Virtual machines might share virtual switches and VLANs with the IP-based storage configurations. IP-based storage includes vSAN, iSCSI, and NFS. This configuration might expose IP-based storage traffic to unauthorized virtual machine users. 

IP-based storage frequently is not encrypted. It can be viewed by anyone with access to this network. To restrict unauthorized users from viewing the IP-based storage traffic, the IP-based storage network must be logically separated from the production traffic. Configuring the IP-based storage adaptors on separate VLANs or network segments from other VMkernels and virtual machines will limit unauthorized users from viewing the traffic.'
  desc 'check', 'If IP-based storage is not used, this is not applicable.

IP-based storage (iSCSI, NFS, vSAN) VMkernel port groups must be in a dedicated VLAN that can be on a standard or distributed virtual switch that is logically separated from other traffic types. The check for this will be unique per environment.

To check a standard switch, from the vSphere Client select the ESXi host and go to Configure >> Networking >> Virtual switches. 

Select a standard switch. For each storage port group (iSCSI, NFS, vSAN), select the port group and click the "Details" button.

Note the VLAN ID associated with each port group and verify that it is dedicated to that purpose and is logically separated from other traffic types.

To check a distributed switch, from the vSphere Client go to Networking >> select and expand a distributed switch. 

For each storage port group (iSCSI, NFS, vSAN), select the port group and navigate to the "Summary" tab. 

Note the VLAN ID associated with each port group and verify that it is dedicated to that purpose and is logically separated from other traffic types.

If any IP-based storage networks are not isolated from other traffic types, this is a finding.'
  desc 'fix', 'Configuration of an IP-based VMkernel will be unique to each environment but, for example, to modify the IP address and VLAN information to the correct network on a standard switch for an iSCSI VMkernel, do the following:

From the vSphere Client, select the ESXi host and go to Configure >> Networking >> VMkernel adapters. 

Select the Storage VMkernel (for any IP-based storage) and click the "Edit" button.

On the Port properties tab, uncheck everything (unless vSAN). 

On the IP Settings tab, enter the appropriate IP address and subnet information and click "OK". 

To configure a standard switch, from the vSphere Client, select the ESXi host and go to Configure >> Networking >> Virtual switches. 

Select a standard switch. 

For each storage port group (iSCSI, NFS, vSAN), select the port group and click the "Edit" button.

On the properties page, enter the appropriate VLAN ID and click "OK".

To configure a distributed switch, from the vSphere Client, go to Networking.

Select and expand a distributed switch. 

For each storage port group (iSCSI, NFS, vSAN), select the port group and navigate to Configure >> Settings >> Properties. 

Click the "Edit" button. 

On the VLAN page, enter the appropriate VLAN type and ID and click "OK".'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46383r719565_chk'
  tag severity: 'medium'
  tag gid: 'V-243108'
  tag rid: 'SV-243108r879887_rule'
  tag stig_id: 'VCTR-67-000052'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46340r719566_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
