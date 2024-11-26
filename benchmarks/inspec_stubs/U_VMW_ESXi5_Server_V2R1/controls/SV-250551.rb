control 'SV-250551' do
  title 'All port groups must be configured with a clear network label.'
  desc 'Each port group must be identified with a network label/name. Names serve as a functional descriptor for the port group. Without these descriptions, identifying port groups and functions becomes difficult as the network becomes more complex.'
  desc 'check', 'From the vSphere Client/vCenter, navigate to Home>> Inventory>> Networking. Individual port groups must be clearly labeled with a meaningful name. 

If individual port groups are not clearly labeled with a meaningful name, this is a finding.'
  desc 'fix', 'From the vSphere Client/vCenter, navigate to Home>> Inventory>> Networking. Clearly label all individual port groups with a meaningful name.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-53986r798650_chk'
  tag severity: 'low'
  tag gid: 'V-250551'
  tag rid: 'SV-250551r798652_rule'
  tag stig_id: 'ESXI5-VMNET-000009'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53940r798651_fix'
  tag 'documentable'
  tag legacy: ['V-39366', 'SV-51224']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
