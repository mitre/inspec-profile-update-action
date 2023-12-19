control 'SV-250560' do
  title 'The system must ensure the virtual switch Promiscuous Mode policy is set to reject.'
  desc 'When promiscuous mode is enabled for a virtual switch, all virtual machines connected to the dvPortgroup have the potential of reading all packets across that network, meaning only the virtual machines connected to that  dvPortgroup. Promiscuous mode is disabled by default on the ESXi Server.'
  desc 'check', %q(Use the vSphere Client to connect to the vCenter Server and as administrator: Go to "Home > Inventory > Hosts and clusters". Select each ESXi host with active virtual switches connected to active VM's requiring securing. Go to the tab "Configuration >> Network >> vSwitch(?) >> Properties >> Ports >> vSwitch >> Default Policies >> Security". Check that the "Promiscuous Mode" is set to "Reject". 

If the "Promiscuous Mode" is not set to "Reject", this is a finding.)
  desc 'fix', 'From the vSphere Client/vCenter Server as administrator: Go to "Home>> Inventory>> Hosts and clusters". Select each ESXi host with active virtual switches connected to active VMs requiring securing. Go to tab "Configuration>> Network>> vSwitch(?)>> Properties>> Ports>> vSwitch>> Default Policies>> Security". Set "Promiscuous Mode" = "Reject".'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-53995r798677_chk'
  tag severity: 'medium'
  tag gid: 'V-250560'
  tag rid: 'SV-250560r798679_rule'
  tag stig_id: 'ESXI5-VMNET-000018'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53949r798678_fix'
  tag 'documentable'
  tag legacy: ['SV-51233', 'V-39375']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
