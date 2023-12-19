control 'SV-250545' do
  title 'All virtual switches must have a clear network label.'
  desc 'Network labels must identify each port group with a name. These names are important because they serve as a functional descriptor for the port group. Without these descriptions, identifying port groups and their functions becomes difficult as the network becomes more complex.'
  desc 'check', 'From the vSphere Client/vCenter, navigate to Home>> Inventory>> Networking. Port groups must be clearly labeled or must be renamed with a meaningful name. 

If all port groups are not clearly labeled with functionally meaningful names, this is a finding.'
  desc 'fix', 'From the vSphere Client/vCenter, navigate to Home>> Inventory>> Networking. Clearly label/rename all port groups with a meaningful name.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-53980r798632_chk'
  tag severity: 'low'
  tag gid: 'V-250545'
  tag rid: 'SV-250545r798634_rule'
  tag stig_id: 'ESXI5-VMNET-000003'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53934r798633_fix'
  tag 'documentable'
  tag legacy: ['V-39358', 'SV-51216']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
