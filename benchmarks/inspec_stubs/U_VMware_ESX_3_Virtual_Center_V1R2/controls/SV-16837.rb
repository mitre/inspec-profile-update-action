control 'SV-16837' do
  title 'The VMware Tools setinfo variable is enabled for virtual machines.'
  desc 'The virtual machine operating system sends informational messages to the ESX Server host through VMware Tools. These messages are setinfo messages and typically contain name-value pairs that define virtual machine characteristics or identifiers that the ESX Server stores.  For instance, a setinfo message may be ipaddress=10.10.15.224.  A setinfo message has fixed formats and lengths. Therefore, the amount of data passed to the ESX Server this way is limited. However, the data flow provides an opportunity for an attacker to stage a DoS attack by writing software that mimics VMware Tools by flooding the ESX Server with packets, and consuming resources needed by virtual machines. To mitigate this, the virtual machine administrator should disable the setinfo variable. This will prevent the guest operating system processes from sending messages to the ESX Server.'
  desc 'check', '1. Login to VirtualCenter with the VI Client and select a virtual machine from the inventory panel.
The configuration page for the virtual machine appears with the Summary tab displayed.
3. Click Options > Advanced > Configuration Parameters to open the Configuration Parameters dialog box.
4. The result should appear as follows:

isolation.tools.setinfo.disable            true

If the isolation.tools.setinfo.disable is not configured to true,  this is a finding.'
  desc 'fix', 'Disable the setinfo variable.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16255r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15895'
  tag rid: 'SV-16837r1_rule'
  tag stig_id: 'ESX0990'
  tag gtitle: 'VMware Tools setinfo variable is enabled'
  tag fix_id: 'F-15856r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Machine Administrator]']
  tag ia_controls: 'ECSC-1'
end
