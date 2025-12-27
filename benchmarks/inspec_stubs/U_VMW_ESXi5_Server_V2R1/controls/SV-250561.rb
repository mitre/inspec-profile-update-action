control 'SV-250561' do
  title 'The system must ensure the dvPortgroup Promiscuous Mode policy is set to reject.'
  desc 'When promiscuous mode is enabled for a dvPortgroup, all virtual machines connected to the dvPortgroup have the potential of reading all packets across that network, meaning only the virtual machines connected to that  dvPortgroup. Promiscuous mode is disabled by default on the ESXi Server, and this is the recommended setting. However, there might be a legitimate reason to enable it for debugging, monitoring or troubleshooting reasons. Security devices might require the ability to see all packets on a vSwitch.  An exception should be made for the dvPortgroups that these applications are connected to, in order to allow for full-time visibility to the traffic on that dvPortgroup.'
  desc 'check', 'If a vNetwork Distributed Switch (vDS) is not configured, this is not applicable.

If the dvPortgroup contains only security devices that continuously monitor all dvPortgroup traffic switch packets, this check is not a finding.

From the vSphere Client/vCenter Server as administrator: 

Go to Home >> Inventory >> Hosts and clusters. 
Select each ESXi host with active virtual switches connected to active VMs requiring securing. 
Go to tab Home >> Inventory >> Networking. Individually select each dvPortgroup, then go to tab Summary >>Edit Settings >>Policies >> Security. 
Verify "Promiscuous Mode" = "Reject".

If the "Promiscuous Mode" parameter is not set to "Reject", this is a finding.'
  desc 'fix', 'From the vSphere Client/vCenter Server as administrator: 

Go to Home >> Inventory >> Hosts and clusters. 
Select each ESXi host with active virtual switches connected to active VMs requiring securing. 
Go to tab Home >> Inventory >> Networking. Individually select each dvPortgroup, then go to tab Summary >> Edit Settings >> Policies >> Security. 
Set the "Promiscuous Mode" keyword to "Reject".'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-53996r798680_chk'
  tag severity: 'medium'
  tag gid: 'V-250561'
  tag rid: 'SV-250561r798682_rule'
  tag stig_id: 'ESXI5-VMNET-000019'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53950r798681_fix'
  tag 'documentable'
  tag legacy: ['V-39376', 'SV-51234']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
