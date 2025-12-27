control 'SV-250558' do
  title 'The system must ensure the virtual switch MAC Address Change policy is set to reject.'
  desc 'If the virtual machine operating system changes the MAC address, it can send frames with an impersonated source MAC address at any time. This allows it to stage malicious attacks on the devices in a network by impersonating a network adaptor authorized by the receiving network. This will prevent VMs from changing their effective MAC address. It will affect applications that require this functionality. An example of an application like this is Microsoft Clustering, which requires systems to effectively share a MAC address. This will also affect how a layer 2 bridge will operate. This will also affect applications that require a specific MAC address for licensing. VMs, guest OSs, and/or applications that require specific MAC settings must be placed in a separate, specially-configured  Portgroup on the vSwitch.'
  desc 'check', 'From the vSphere Client, connect to the vCenter Server and as administrator: 
Go to "Home>> Inventory>> Hosts and clusters". Select each ESXi host with active virtual switches connected to active VMs requiring securing. Go to tab "Configuration>> Network>> vSwitch(?)>> Properties>> Ports>> vSwitch>> Default Policies>> Security". Verify the "Mac Address Changes" = "Reject".

If the VM/guest OS/application requires a specific MAC Address parameter setting for normal operation and is placed in a separate, specially-configured Portgroup ( with "Mac Address Changes" = "Accept") on the vSwitch, this is not a finding.

If the VM/guest OS/application does not require a specific MAC Address parameter setting for normal operation and the "Mac Address Changes" parameter is not set to "Reject", this is a finding.'
  desc 'fix', 'From the vSphere Client, connect to the vCenter Server and as administrator: 
Go to "Home>> Inventory>> Hosts and clusters". Select each ESXi host with active virtual switches connected to active VMs requiring securing. Go to tab "Configuration>> Network>> vSwitch(?)>> Properties>> Ports>> vSwitch>> Default Policies>> Security". Change the "Mac Address Changes" = "Reject".'
  impact 0.7
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-53993r798671_chk'
  tag severity: 'high'
  tag gid: 'V-250558'
  tag rid: 'SV-250558r798673_rule'
  tag stig_id: 'ESXI5-VMNET-000016'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53947r798672_fix'
  tag 'documentable'
  tag legacy: ['SV-51231', 'V-39373']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
