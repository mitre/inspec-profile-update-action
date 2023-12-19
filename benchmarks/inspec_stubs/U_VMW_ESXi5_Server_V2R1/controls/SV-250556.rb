control 'SV-250556' do
  title 'The system must ensure that the dvPortgroup Forged Transmits policy is set to reject.'
  desc 'If the virtual machine operating system changes the MAC address, the operating system can send frames with an impersonated source MAC address at any time. This allows an operating system to stage malicious attacks on the devices in a network by impersonating a network adaptor authorized by the receiving network. Forged transmissions should be set to accept by default. This means the virtual switch does not compare the source and effective MAC addresses. To protect against MAC address impersonation, all virtual switches should have forged transmissions set to reject.'
  desc 'check', 'If a vNetwork Distributed Switch (vDS) is not configured, this is not applicable.

The "Forged Transmits" parameter must be set to "Reject" on all dvPortgroups. From the vSphere Client/vCenter as administrator: 

Go to Home >> Inventory >> Networking. Select each dvPortgroup connected to VMs. Go to tab Summary >> Edit Settings >> Policies >> Security. Verify "Forged Transmits" = "Reject".

If the "Forged Transmits" parameter is not set to "Reject" on all dvPortgroups, this is a finding.'
  desc 'fix', 'The "Forged Transmits" parameter must be set to "Reject" on all dvPortgroups.

From the vSphere Client/vCenter as administrator: 

Go to Home >> Inventory >> Networking. 
Select each dvPortgroup connected to VMs. 
Go to tab Summary >> Edit Settings >> Policies >> Security. 
Set "Forged Transmits" = "Reject".'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-53991r798665_chk'
  tag severity: 'medium'
  tag gid: 'V-250556'
  tag rid: 'SV-250556r798667_rule'
  tag stig_id: 'ESXI5-VMNET-000014'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53945r798666_fix'
  tag 'documentable'
  tag legacy: ['SV-51229', 'V-39371']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
