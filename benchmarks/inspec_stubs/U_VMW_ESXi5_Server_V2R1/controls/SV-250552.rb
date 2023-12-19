control 'SV-250552' do
  title 'All port groups must be configured to a value other than that of the native VLAN.'
  desc 'ESXi does not use the concept of native VLAN. Frames with VLAN specified in the port group will have a tag, but frames with VLAN not specified in the port group are not tagged and therefore will end up as belonging to native VLAN of the physical switch. For example, frames on VLAN 1 from a Cisco physical switch will be untagged, because this is considered as the native VLAN. However, frames from ESXi specified as VLAN 1 will be tagged with a "1"; therefore, traffic from ESXi that is destined for the native VLAN will not be correctly routed (because it is tagged with a "1" instead of being untagged), and traffic from the physical switch coming from the native VLAN will not be visible (because it is not tagged). If the ESXi virtual switch port group uses the native VLAN ID, traffic from those VMs will not be visible to the native VLAN on the switch, because the switch is expecting untagged traffic.'
  desc 'check', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively. Start the ESXi Shell service, where/as required. As root, log in to the ESXi Shell and run the following command.

# esxcli network vswitch standard portgroup list

If the default value (1) for the native VLAN is being used, this is a finding. 

Re-enable Lockdown Mode on the host.'
  desc 'fix', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. 

Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. 
If connecting to vCenter Server, click on the desired host. 
Click the Configuration tab. 
Click Software, Security Profile, Services, Properties, ESXi Shell, and Options, respectively.
Start the ESXi Shell service, where/as required.

As root, log in to the ESXi Shell and run the command to set the value to something other than the default value.
esxcli network vswitch standard portgroup set --portgroup-name=<name> --vlan-id=<non-default_id_number>

Re-enable Lockdown Mode on the host.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-53987r798653_chk'
  tag severity: 'medium'
  tag gid: 'V-250552'
  tag rid: 'SV-250552r798655_rule'
  tag stig_id: 'ESXI5-VMNET-000010'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53941r798654_fix'
  tag 'documentable'
  tag legacy: ['SV-51225', 'V-39367']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
