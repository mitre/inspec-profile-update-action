control 'SV-77759' do
  title 'The system must protect the confidentiality and integrity of transmitted information by protecting IP based management traffic.'
  desc 'Virtual machines might share virtual switches and VLANs with the IP-based storage configurations. IP-based storage includes iSCSI and NFS. This configuration might expose IP-based storage traffic to unauthorized virtual machine users. IP-based storage frequently is not encrypted. It can be viewed by anyone with access to this network. To restrict unauthorized users from viewing the IP-based storage traffic, the IP-based storage network must be logically separated from the production traffic. Configuring the IP-based storage adaptors on separate VLANs or network segments from other VMkernels and Virtual Machines will limit unauthorized users from viewing the traffic.'
  desc 'check', 'IP-Based storage (iSCSI, NFS, VSAN) VMkernel port groups must be in a dedicated VLAN that can be on a common standard or distributed virtual switch that is logically separated from other traffic types.  The check for this will be unique per environment.  From the vSphere Client select the ESXi host and go to Configuration >> Networking and review the VLANs associated with any IP-Based storage VMkernels and verify they are dedicated for that purpose and are logically separated from other functions.

If any IP-Based storage networks are not isolated from other traffic types, this is a finding.

If IP-based storage is not used, this is not applicable.'
  desc 'fix', 'Configuration of an IP-Based VMkernel will be unique to each environment but for example to modify the IP address and VLAN information to the correct network on a standard switch for an iSCSI VMkernel do the following:

From the vSphere Client select the ESXi host and go to Configuration >> Networking >> On the vSwitch that contains the iSCSI VMkernel select Properties.  Select the iSCSI VMkernel and click Edit >> On the General tab uncheck everything and set the appropriate VLAN ID >> Go to the IP Settings tab >> Enter the appropriate IP address and subnet information and click OK.'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-64003r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63269'
  tag rid: 'SV-77759r1_rule'
  tag stig_id: 'ESXI-06-000050'
  tag gtitle: 'SRG-OS-000423-VMM-001700'
  tag fix_id: 'F-69187r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
