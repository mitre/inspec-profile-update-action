control 'SV-16866' do
  title 'Guest OS selection does not match installed OS.'
  desc 'Selecting the correct guest OS for each virtual machine is important. ESX Servers optimize certain internal configurations on the basis of this selection. For this reason, it is important to set the guest operating system correctly. The correct guest operating selection can greatly aid the operating system chosen and may cause significant performance degradation if there is a mismatch between the selection and the OS actually running in the virtual machine. The performance degradation may be similar to running an unsupported OS on the ESX Server. Selecting the wrong guest OS is not likely to cause a virtual machine to run incorrectly, but it could degrade the virtual machine’s performance.'
  desc 'check', 'Select a Linux and Windows server to verify that the OS selections are accurate.  For instance, Red Hat EL 4 should be selected as RedHat EL 4, not Linux, Suse, etc.  

1. Login to VirtualCenter with the VI Client and select the virtual machine from the inventory panel. 
2. Click Edit settings. Click Options > General Options.  Review the Guest Operating System and Version to obtain the guest operating system selection.
3. Review the selected OS and the actual OS version running.  If they are different, this is a finding.'
  desc 'fix', 'Select the correct operating system for all virtual machines.'
  impact 0.5
  ref 'DPMS Target VMware Virtual Machine 3.x/4.x'
  tag check_id: 'C-16277r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15924'
  tag rid: 'SV-16866r1_rule'
  tag stig_id: 'ESX1180'
  tag gtitle: 'Guest OS selection does not match installed OS'
  tag fix_id: 'F-15875r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Guest Administrator]']
  tag ia_controls: 'ECSC-1'
end
