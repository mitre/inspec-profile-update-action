control 'SV-38931' do
  title 'The DHCP client must be disabled if not needed.'
  desc 'DHCP allows for the unauthenticated configuration of network parameters on the system by exchanging information with a DHCP server.'
  desc 'fix', "Disable the system's DHCP client. 

Edit /etc/rc.tcpip, comment out the line starting dhcpcd.  Reboot the system to ensure the DHCP client has been disabled fully.  Configure a static IP for the system, if network connectivity is required."
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-22548'
  tag rid: 'SV-38931r1_rule'
  tag stig_id: 'GEN007840'
  tag gtitle: 'GEN007840'
  tag fix_id: 'F-33172r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
