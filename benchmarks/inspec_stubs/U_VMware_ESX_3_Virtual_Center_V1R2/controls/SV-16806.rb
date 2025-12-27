control 'SV-16806' do
  title 'VirtualCenter virtual machine does not have a CPU reservation.'
  desc 'Virtual machine settings affect the availability of the VirtualCenter virtual machine as well.  If the virtual machine is not configured with resource reservations, there is no guarantee that the resources will be available.'
  desc 'check', '1. Log into VirtualCenter with the VI Client.
2. In the Inventory panel on the left, select the host that has the VirtualCenter virtual machine.
3. Select the Resource Allocation Tab and view the reservation for the virtual machine CPU.  Under View: Select CPU.  
4. If the virtual machine reservation says 0, this is a finding.'
  desc 'fix', 'Reserve CPU resources for the VirtualCenter virtual machine.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16222r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15865'
  tag rid: 'SV-16806r1_rule'
  tag stig_id: 'ESX0660'
  tag gtitle: 'VirtualCenter virtual machine has no CPU reserve.'
  tag fix_id: 'F-15825r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
  tag ia_controls: 'ECSC-1'
end
