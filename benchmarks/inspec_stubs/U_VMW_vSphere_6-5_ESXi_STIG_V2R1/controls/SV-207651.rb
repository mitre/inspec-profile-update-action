control 'SV-207651' do
  title 'The ESXi host must protect the confidentiality and integrity of transmitted information by utilizing different TCP/IP stacks where possible.'
  desc 'There are three different TCP/IP stacks by default available on ESXi now which are Default, Provisioning, and vMotion.  To better protect and isolate sensitive network traffic within ESXi admins must configure each of these stacks.  Additional custom TCP/IP stacks can be created if desired.'
  desc 'check', 'From the vSphere Web Client select the ESXi Host and go to Configure >> Networking >> TCP/IP configuration. Review the default system TCP/IP stacks and verify they are configured with the appropriate IP address information.

If vMotion and Provisioning VMKernels are in use and are not utilizing their own TCP/IP stack, this is a finding.'
  desc 'fix', 'From the vSphere Web Client select the ESXi Host and go to Configure >> Networking >> TCP/IP configuration >> Select a TCP/IP stack >> Click Edit >> Enter the appropriate site specific IP address information for the particular TCP/IP stack and click OK.'
  impact 0.3
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7906r364352_chk'
  tag severity: 'low'
  tag gid: 'V-207651'
  tag rid: 'SV-207651r380176_rule'
  tag stig_id: 'ESXI-65-000052'
  tag gtitle: 'SRG-OS-000423-VMM-001700'
  tag fix_id: 'F-7906r364353_fix'
  tag 'documentable'
  tag legacy: ['V-94051', 'SV-104137']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
