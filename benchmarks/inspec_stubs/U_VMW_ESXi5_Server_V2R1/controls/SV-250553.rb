control 'SV-250553' do
  title 'All port groups must not be configured to VLAN 4095 except for Virtual Guest Tagging (VGT).'
  desc 'When a port group is set to VLAN 4095, this activates VGT mode. In this mode, the vSwitch passes all network frames to the guest VM without modifying the VLAN tags, leaving it up to the guest to deal with them. VLAN 4095 should be used only if the guest has been specifically configured to manage VLAN tags itself. If VGT is enabled inappropriately, it might cause denial-of-service or allow a guest VM to interact with traffic on an unauthorized VLAN.'
  desc 'check', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell, and Options, respectively. Start the ESXi Shell service, where/as required.

As root, log in to the ESXi Shell and run the following command.
# esxcli network vswitch standard portgroup list

If the VGT value (4095) is set and the guest is not configured to handle VLAN tags, this is a finding.

Re-enable Lockdown Mode on the host.'
  desc 'fix', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell, and Options, respectively. Start the ESXi Shell service, where/as required.

As root, log in to the ESXi Shell and run the command to set the value to something other than the VGT 4095 value.
esxcli network vswitch standard portgroup set --portgroup-name=<name> --vlan-id=<non-default_id_number>

Re-enable Lockdown Mode on the host.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-53988r798656_chk'
  tag severity: 'medium'
  tag gid: 'V-250553'
  tag rid: 'SV-250553r798658_rule'
  tag stig_id: 'ESXI5-VMNET-000011'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53942r798657_fix'
  tag 'documentable'
  tag legacy: ['V-39368', 'SV-51226']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
