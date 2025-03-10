control 'SV-216401' do
  title 'Wireless network adapters must be disabled.'
  desc 'The use of wireless networking can introduce many different attack vectors into the organization’s network. Common attack vectors such as malicious association and ad hoc networks will allow an attacker to spoof a wireless access point (AP), allowing validated systems to connect to the malicious AP and enabling the attacker to monitor and record network traffic. These malicious APs can also serve to create a man-in-the-middle attack or be used to create a denial-of-service to valid network resources.'
  desc 'check', 'This is N/A for systems that do not have wireless network adapters.

Verify that there are no wireless interfaces configured on the system:

# ifconfig -a


eth0      Link encap:Ethernet  HWaddr b8:ac:6f:65:31:e5  
          inet addr:192.168.2.100  Bcast:192.168.2.255  Mask:255.255.255.0
          inet6 addr: fe80::baac:6fff:fe65:31e5/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:2697529 errors:0 dropped:0 overruns:0 frame:0
          TX packets:2630541 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:2159382827 (2.0 GiB)  TX bytes:1389552776 (1.2 GiB)
          Interrupt:17 

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:2849 errors:0 dropped:0 overruns:0 frame:0
          TX packets:2849 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:2778290 (2.6 MiB)  TX bytes:2778290 (2.6 MiB)


If a wireless interface is configured, it must be documented and approved by the local Authorizing Official.

If a wireless interface is configured and has not been documented and approved, this is a finding.'
  desc 'fix', 'Configure the system to disable all wireless network interfaces.'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17637r371291_chk'
  tag severity: 'medium'
  tag gid: 'V-216401'
  tag rid: 'SV-216401r603267_rule'
  tag stig_id: 'SOL-11.1-050480'
  tag gtitle: 'SRG-OS-000481'
  tag fix_id: 'F-17635r371292_fix'
  tag 'documentable'
  tag legacy: ['V-72827', 'SV-87479']
  tag cci: ['CCI-002418', 'CCI-001443', 'CCI-001444']
  tag nist: ['SC-8', 'AC-18 (1)', 'AC-18 (1)']
end
