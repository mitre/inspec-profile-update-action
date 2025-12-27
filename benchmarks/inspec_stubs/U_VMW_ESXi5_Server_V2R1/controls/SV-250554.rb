control 'SV-250554' do
  title 'All port groups must not be configured to VLAN values reserved by upstream physical switches.'
  desc 'Physical vendor-specific switches reserve certain VLAN IDs for internal purposes and often disallow traffic configured to these values. Use of reserved VLAN IDs can result in a network denial-of-service.'
  desc 'check', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively. Start the ESXi Shell service, where/as required. Determine the site-specific switch reserved VLAN, configuration requirements via vendor documentation. For example, Cisco Catalyst switches typically reserve VLANs 1001-1024 and 4094 and Nexus switches typically reserve 3968-4047 and 4094. As root, log in to the ESXi Shell and run the command:
# esxcli network vswitch standard portgroup list

If the VLAN ID is set to a vendor-reserved value, this is a finding.

Re-enable Lockdown Mode on the host.'
  desc 'fix', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell, and Options, respectively. Start the ESXi Shell service, where/as required.

As root, log in to the ESXi Shell and run the command to set the value to something other than the vendor-specific reserved value.
esxcli network vswitch standard portgroup set --portgroup-name=<name> --vlan-id=<non-default_id_number>;

Re-enable Lockdown Mode on the host.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-53989r798659_chk'
  tag severity: 'medium'
  tag gid: 'V-250554'
  tag rid: 'SV-250554r798661_rule'
  tag stig_id: 'ESXI5-VMNET-000012'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53943r798660_fix'
  tag 'documentable'
  tag legacy: ['SV-51227', 'V-39369']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
