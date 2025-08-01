control 'SV-16756' do
  title 'Forged Transmits are set to “Accept” on virtual switches'
  desc 'Each virtual NIC in a virtual machine has an initial MAC address assigned when the virtual adapter is created. Each virtual adapter also has an effective MAC address that filters out incoming network traffic with a destination MAC address different from the effective MAC address. A virtual adapter’s effective MAC address and initial MAC address are the same when they are initially created. However, the virtual machine’s operating system may alter the effective MAC address to another value at any time. If the virtual machine operating system changes the MAC address, the operating system can send frames with an impersonated source MAC address at any time. This allows an operating system to stage malicious attacks on the devices in a network by impersonating a network adapter authorized by the receiving network. SAs can use virtual switch security profiles on ESX Server hosts to protect against this type of attack by setting two options on virtual switches. These options are MAC Address Changes and Forged Transmits.

Forged transmissions are set to accept by default. This means the virtual switch does
not compare the source and effective MAC addresses. The Forged Transmits option setting
affects traffic transmitted from a virtual machine. If this option is set to reject, the virtual switch compares the source MAC address being transmitted by the operating system with the effective MAC address for its virtual network adapter to see if they are the same. If the MAC addresses are different, the virtual switch drops the frame. The guest operating system will not detect that its virtual network adapter cannot send packets using the different MAC address. To protect against MAC address impersonation, all virtual switches will have forged transmissions set to reject.'
  desc 'check', '1. Log into VirtualCenter with the VI Client and select the ESX server from the inventory panel.
    The hardware configuration page for the server appears.
2. Click the Configuration tab, and click Networking.
3. Click Properties for the virtual switch whose layer 2 policy you want to review.
4. In the Properties dialog box for the virtual switch, click the Ports tab.
5. Select the virtual switch item and click Edit.
6. In the Properties dialog box for the virtual switch, click the Security tab.
7. Verify the Forged Transmits is set to Reject.  If it is not, this is a finding.'
  desc 'fix', 'Configure the Forged Transmits Policy to “Reject”.'
  impact 0.7
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16107r1_chk'
  tag severity: 'high'
  tag gid: 'V-15817'
  tag rid: 'SV-16756r1_rule'
  tag stig_id: 'ESX0260'
  tag gtitle: 'Forged Transmits are set to "Accept".'
  tag fix_id: 'F-15769r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
