control 'SV-77763' do
  title 'The system must protect the confidentiality and integrity of transmitted information by utilizing different TCP/IP stacks where possible.'
  desc 'There are three different TCP/IP stacks by default available on ESXi now which are Default, Provisioning, and vMotion.  To better protect and isolate sensitive network traffic within ESXi admins must configure each of these stacks.  Additional custom TCP/IP stacks can be created if desired.'
  desc 'check', 'From the vSphere Web Client select the ESXi Host and go to Manage >> Networking >> TCP/IP configuration.  Review the default system TCP/IP stacks and verify they are configured with the appropriate IP address information.

If any system TCP/IP stack is configured and not in use by a VMkernel adapter, this is a finding.'
  desc 'fix', 'From the vSphere Web Client select the ESXi Host and go to Manage >> Networking >> TCP/IP configuration >> Select a TCP/IP stack >> Click Edit >> Enter the appropriate site specific IP address information for the particular TCP/IP stack and click OK.'
  impact 0.3
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-64007r1_chk'
  tag severity: 'low'
  tag gid: 'V-63273'
  tag rid: 'SV-77763r1_rule'
  tag stig_id: 'ESXI-06-000052'
  tag gtitle: 'SRG-OS-000423-VMM-001700'
  tag fix_id: 'F-69191r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
