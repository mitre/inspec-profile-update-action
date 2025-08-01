control 'SV-16807' do
  title 'VirtualCenter virtual machine does not have a memory reservation.'
  desc 'Virtual machine settings affect the availability of the VirtualCenter virtual machine as well.  If the virtual machine is not configured with resource reservations, there is no guarantee that the resources will be available.'
  desc 'check', '1. Log into VirtualCenter with the VI Client.
2. In the Inventory panel on the left, select the host that has the VirtualCenter virtual machine.
3. Select the Resource Allocation Tab and view the reservation for the virtual machine Memory.  Under View: Select Memory.  
4. If the virtual machine reservation says 0, this is a finding.'
  desc 'fix', 'Reserve Memory resources for the VirtualCenter virtual machine.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16223r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15866'
  tag rid: 'SV-16807r1_rule'
  tag stig_id: 'ESX0670'
  tag gtitle: 'VirtualCenter vm has no memory reservation.'
  tag fix_id: 'F-15826r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
  tag ia_controls: 'ECSC-1'
end
