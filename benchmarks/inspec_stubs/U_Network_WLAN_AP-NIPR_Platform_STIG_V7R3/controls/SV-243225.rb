control 'SV-243225' do
  title 'The network device must be configured to only permit management traffic that ingresses and egresses the out-of-band management (OOBM) interface.'
  desc 'The OOBM access switch will connect to the management interface of the managed network elements. The management interface can be a true OOBM interface or a standard interface functioning as the management interface. In either case, the management interface of the managed network element will be directly connected to the OOBM network. (See SRG-NET-000205-RTR-000012.)

Network boundaries, also known as managed interfaces, include, for example, gateways, routers, firewalls, guards, network-based malicious code analysis, and virtualization systems, or encrypted tunnels implemented within a security architecture (e.g., routers protecting firewalls or application gateways residing on protected subnetworks). Subnetworks that are physically or logically separated from internal networks are referred to as demilitarized zones (DMZs). Methods used for prohibiting interfaces within organizational information systems include, for example, restricting external web traffic to designated web servers within managed interfaces and prohibiting external traffic that appears to be spoofing internal addresses.'
  desc 'check', 'Review the device configuration to determine if the OOB management interface is assigned an appropriate IP address from the authorized OOB management network.

If an IP address assigned to the interface is not from an authorized OOB management network, this is a finding.'
  desc 'fix', 'Configure the network device so that only management traffic that ingresses and egresses the OOBM interface is permitted.'
  impact 0.5
  ref 'DPMS Target Network WLAN AP-NIPR Platform'
  tag check_id: 'C-46500r720128_chk'
  tag severity: 'medium'
  tag gid: 'V-243225'
  tag rid: 'SV-243225r720130_rule'
  tag stig_id: 'WLAN-NW-001200'
  tag gtitle: 'SRG-NET-000205'
  tag fix_id: 'F-46457r720129_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
