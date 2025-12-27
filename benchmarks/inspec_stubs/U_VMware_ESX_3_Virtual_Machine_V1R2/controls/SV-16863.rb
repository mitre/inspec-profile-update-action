control 'SV-16863' do
  title 'Unused hardware is enabled in virtual machines.'
  desc 'Virtual machines can connect or disconnect hardware devices. These devices may be network adapters, CD-ROM drives, USB drives, etc. Attackers may use this capability via non-privileged users or processes to breach virtual machines in several ways. An attacker that has access to a virtual machine may connect a CD-ROM drive and access sensitive information on the media left in the drive. Another action an attacker may perform is disconnecting the network adapter to isolate the virtual machine from its network resulting in a DoS. Therefore, as a general security precaution, SAs will remove any unneeded or unused hardware devices.  If permanently removing a device is not feasible, SAs can restrict a virtual machine process or user from connecting or disconnecting devices from within the guest operating system.'
  desc 'check', '1. Login to VirtualCenter with the VI Client and select the virtual machine from the inventory panel. 
2. Click Edit settings. 
3. Click the Hardware tab.
4. Compare the virtual machine requirements documentation for the virtual machine to ensure that only the required devices are configured in the hardware tab.  All devices (serial ports, network adapters, CD-ROMs, etc.) that are listed in the hardware tab and not in the virtual machine documentation will be a finding.  If no virtual machine requirements exist, this is a finding.'
  desc 'fix', 'Disable or remove all unused hardware in virtual machines.'
  impact 0.5
  ref 'DPMS Target VMware Virtual Machine 3.x/4.x'
  tag check_id: 'C-16276r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15921'
  tag rid: 'SV-16863r1_rule'
  tag stig_id: 'ESX1170'
  tag gtitle: 'Unused hardware is enabled on virtual machines'
  tag fix_id: 'F-15874r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Guest Administrator]']
end
