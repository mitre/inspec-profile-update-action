control 'SV-250557' do
  title 'The system must ensure the dvPortGroup MAC Address Change policy is set to reject.'
  desc 'If the virtual machine operating system changes the MAC address, it can send frames with an impersonated source MAC address at any time. This allows it to stage malicious attacks on the devices in a network by impersonating a network adaptor authorized by the receiving network. This will prevent VMs from changing their effective MAC address. It will affect applications that require this functionality. An example of an application like this is Microsoft Clustering, which requires systems to effectively share a MAC address. This will also affect how a layer 2 bridge will operate. This will also affect applications that require a specific MAC address for licensing. VMs, guest OSs, and/or applications that require specific MAC settings must be placed in a separate, specially-configured  dvPortgroup on the vDistributed Switch (vDS).'
  desc 'check', 'If a vNetwork Distributed Switch (vDS) is not configured, this is not applicable.

Check the setting by using the vSphere Client to connect to the vCenter Server and as administrator: 
Go to Home >> Inventory >> Networking. Select each dvPortgroup connected to active VMs requiring securing. Go to tab Summary >> Edit Settings >> Policies >> Security. Check the "Mac Address Changes" = "Reject".

If the VM/guest OS/application requires a specific MAC Address parameter setting for normal operation and is placed in a separate, specially-configured dvPortgroup ( with "Mac Address Changes" = "Accept") on the vDistributed Switch (vDS), this is not a finding.

If the VM/guest OS/application does not require a specific MAC Address parameter setting for normal operation and the "Mac Address Changes" parameter is not set to "Reject", this is a finding.'
  desc 'fix', 'Verify by using the vSphere Client to connect to the vCenter Server and as administrator: 
Go to Home >> Inventory >> Networking. Select each dvPortgroup connected to active VMs requiring securing. Go to tab Summary >> Edit Settings >> Policies >> Security. Change the "Mac Address Changes" = "Reject".'
  impact 0.7
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-53992r798668_chk'
  tag severity: 'high'
  tag gid: 'V-250557'
  tag rid: 'SV-250557r798670_rule'
  tag stig_id: 'ESXI5-VMNET-000015'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53946r798669_fix'
  tag 'documentable'
  tag legacy: ['V-39372', 'SV-51230']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
