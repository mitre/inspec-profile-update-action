control 'SV-77757' do
  title 'The system must protect the confidentiality and integrity of transmitted information by protecting ESXi management traffic.'
  desc 'The vSphere management network provides access to the vSphere management interface on each component. Services running on the management interface provide an opportunity for an attacker to gain privileged access to the systems. Any remote attack most likely would begin with gaining entry to this network.'
  desc 'check', 'The Management VMkernel port group should in a dedicated VLAN that can be on a common standard or distributed virtual switch as long as the Management VLAN is not shared by any other function and it not routed to anything other than management related functions such as vCenter.  The check for this will be unique per environment.  From the vSphere Client select the ESXi host and go to Configuration >> Networking and review the VLAN associated with the Management VMkernel and verify they are dedicated for that purpose and are logically separated from other functions.

If the network segment is routed, except to networks where other management-related entities are located such as vCenter, this is a finding.

If production virtual machine traffic is routed to this network, this is a finding.'
  desc 'fix', 'Configuration of the Management VMkernel will be unique to each environment but for example to modify the IP address and VLAN information to the correct network on a standard switch do the following:

From the vSphere Client select the ESXi host and go to Configuration >> Networking >> On the vSwitch that contains the Management VMkernel select Properties.  Select the Management VMkernel and click Edit >> On the General tab uncheck everything but "Management Traffic" and set the appropriate VLAN ID >> Go to the IP Settings tab >> Enter the appropriate IP address and subnet information and click OK.'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-64001r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63267'
  tag rid: 'SV-77757r1_rule'
  tag stig_id: 'ESXI-06-000049'
  tag gtitle: 'SRG-OS-000423-VMM-001700'
  tag fix_id: 'F-69185r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
