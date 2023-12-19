control 'SV-239306' do
  title 'The ESXi host must protect the confidentiality and integrity of transmitted information by using different TCP/IP stacks where possible.'
  desc 'Three different TCP/IP stacks are available by default on ESXi: Default, Provisioning, and vMotion. 

To better protect and isolate sensitive network traffic within ESXi, administrators must configure each of these stacks. Additional custom TCP/IP stacks can be created if desired.'
  desc 'check', 'From the vSphere Client, select the ESXi host and go to Configure >> Networking >> TCP/IP configuration. 

Review the default system TCP/IP stacks and verify they are configured with the appropriate IP address information.

If vMotion and Provisioning VMKernels are in use and are not using their own TCP/IP stack, this is a finding.'
  desc 'fix', 'From the vSphere Client, select the ESXi host and go to Configure >> Networking >> TCP/IP configuration.

Select a TCP/IP stack and click "Edit". 

Enter the appropriate site-specific IP address information for the particular TCP/IP stack and click "OK".'
  impact 0.3
  ref 'DPMS Target VMware vSphere 6.7 ESXi'
  tag check_id: 'C-42539r674845_chk'
  tag severity: 'low'
  tag gid: 'V-239306'
  tag rid: 'SV-239306r854602_rule'
  tag stig_id: 'ESXI-67-000052'
  tag gtitle: 'SRG-OS-000423-VMM-001700'
  tag fix_id: 'F-42498r674846_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
