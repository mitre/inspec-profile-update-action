control 'SV-234199' do
  title 'The FortiGate device must prohibit the use of all unnecessary and/or non-secure functions, ports, protocols, and/or services.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable unused or unnecessary physical and logical ports/protocols on information systems.

Network devices are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the network device must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved. Some network devices have capabilities enabled by default; if these capabilities are not necessary, they must be disabled. If a particular capability is used, then it must be documented and approved.'
  desc 'check', 'Log in to FortiGate GUI with Super-Admin privileges.

1. Click Policy and Objects.
2. Click Services, and then review services, functions, and ports that are allowed by the firewall.
3. Next, open a CLI console, via SSH or available from the GUI.
4. Run the following commands:
# show firewall policy
# show firewall policy6

Review policies to ensure that no restricted services, ports, protocols or functions are allowed. FortiGate is configured to deny by default, so if a service, port, protocol, or function is not specifically allowed, it will be denied. 

If restricted functions, ports, protocols, and/or services are allowed by the firewall, this is a finding.

or 

Log in to the FortiGate GUI with Super-Admin privilege.
1. Open a CLI console over SSH or available from the GUI.
2. Run the following 
# show full-configuration system interface
3. Review configuration for unnecessary services.

If unnecessary services are configured, this is a finding.

Review the PPSM CAL and determine which functions, ports, protocols, and/or services must be disabled or restricted.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.
1. Click Policy and Objects.
2. Click IPv4 or IPv6 Policy.
3. Click +Create New.
4. Name the policy, and then select Incoming and Outgoing Interfaces.
5. Create policies with authorized sources and destinations.
6. Set action to DENY.
7. Ensure Enable this policy is toggled to right.
8. Click OK.
9. Ensure a policy is created for each interface and that every PPSM CAL and VA mitigation is covered.

Traffic is denied by default and policies must be configured to allow traffic that meets PPSM CAL and VA guidelines.

or 

Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following 
  # config system interface
      # edit {INTERFACE-NAME}
         # set {DHCP-RELAY-SERVICE | PPTP-CLIENT | ARPFORWARD | BROADCAST-FORWARD | L2FORWARD | ICMP-REDIRECT | VLANFORWARD | STPFORWARD  | LLDP-TRANSMISSION} disable
      # end
Create a new line for each service in {} that needs to be removed.'
  impact 0.7
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37384r611784_chk'
  tag severity: 'high'
  tag gid: 'V-234199'
  tag rid: 'SV-234199r628878_rule'
  tag stig_id: 'FGFW-ND-000200'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-37349r628877_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
