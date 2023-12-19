control 'SV-16754' do
  title 'The MAC Address Change Policy is set to “Accept” for virtual switches.'
  desc 'Each virtual NIC in a virtual machine has an initial MAC address assigned when the virtual adapter is created. Each virtual adapter also has an effective MAC address that filters out incoming network traffic with a destination MAC address different from the effective MAC address. A virtual adapter’s effective MAC address and initial MAC address are the same when they are initially created. However, the virtual machine’s operating system may alter the effective MAC address to another value at any time. If the virtual machine operating system changes the MAC address, the operating system can send frames with an impersonated source MAC address at any time. This allows an operating system to stage malicious attacks on the devices in a network by impersonating a network adapter authorized by the receiving network. System administrators can use virtual switch security profiles on ESX Server hosts to protect against this type of attack by setting two options on the virtual switches. These options are MAC Address Changes and Forged Transmits.

MAC address changes are set to accept by default meaning that the virtual switch accepts requests to change the effective MAC address. The MAC Address Changes option setting affects traffic received by a virtual machine. To protect against MAC impersonation this option will be set to reject, ensuring the virtual switch does not honor requests to change the effective MAC address to anything other than the initial MAC address. Setting this to reject disables the port that the virtual network adapter used to send the request. Therefore, the virtual network adapter does not receive any more frames until it configures the effective MAC address to match the initial MAC address. The guest operating system will not detect that the MAC address change has not been honored.'
  desc 'check', '1. Log into VirtualCenter with the VI Client and select the ESX server from the inventory panel.
    The hardware configuration page for the server appears.
2. Click the Configuration tab, and click Networking.
3. Click Properties for the virtual switch whose layer 2 policy you want to review.
4. In the Properties dialog box for the virtual switch, click the Ports tab.
5. Select the virtual switch item and click Edit.
6. In the Properties dialog box for the virtual switch, click the Security tab.
7. Verify the MAC Address Changes is set to Reject. If it is not, this is a finding.

Caveat: This is not applicable for legacy applications, clustered environments, and licensing issues if documented and approved by the IAO/SA.'
  desc 'fix', 'Configure the MAC Address Changes Policy to “Reject”.'
  impact 0.7
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16105r1_chk'
  tag severity: 'high'
  tag gid: 'V-15815'
  tag rid: 'SV-16754r1_rule'
  tag stig_id: 'ESX0250'
  tag gtitle: 'MAC Address Change Policy is set to "Accept".'
  tag fix_id: 'F-15768r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
