control 'SV-16836' do
  title 'VMware Tools drag and drop capabilities are enabled for virtual machines.'
  desc 'The drag and drop operation may be used to transfer files from the guest virtual machine to the computer connecting to the virtual machine via the VI Console.  Files may be moved from the guest virtual machine to the VI Console computer through the drag and drop functionality. This functionality has several potential damaging consequences. The file moved to the VI Console computer may be so large that it fills the hard disk on the system, may contain sensitive information, or may contain malicious code. These scenarios could potentially cause a denial of service to the VI Console computer, expose sensitive information to unauthorized users, or run malicious code.'
  desc 'check', '1. Login to VirtualCenter with the VI Client and select a virtual machine from the inventory panel.
The configuration page for the virtual machine appears with the Summary tab displayed.
3. Click Options > Advanced > Configuration Parameters to open the Configuration Parameters dialog box.
4. Verify the following is displayed in the result:

isolation.tools.dnd.disable		true

If this is not present, this is a finding.'
  desc 'fix', 'Disable drag and drop in VMware Tools.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16254r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15894'
  tag rid: 'SV-16836r1_rule'
  tag stig_id: 'ESX0980'
  tag gtitle: 'VMware Tools drag and drop capabilities'
  tag fix_id: 'F-15855r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Machine Administrator]']
end
