control 'SV-248835' do
  title 'OL 8 must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services as defined in the Ports, Protocols, and Services Management (PPSM) Category Assignments List (CAL) and vulnerability assessments.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems. 
 
Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component. 
 
To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality-of-life issues.'
  desc 'check', 'Inspect the firewall configuration and running services to verify it is configured to prohibit or restrict the use of functions, ports, protocols, and/or services that are unnecessary or prohibited. 
 
Check which services are currently active with the following command: 
 
$ sudo firewall-cmd --list-all 
 
custom (active) 
target: DROP 
icmp-block-inversion: no 
interfaces: ens33 
sources:  
services: dhcpv6-client dns http https ldaps rpc-bind ssh 
ports:  
masquerade: no 
forward-ports:  
icmp-blocks:  
rich rules:  
 
Ask the System Administrator for the site or program PPSM Component Local Service Assessment (CLSA). Verify the services allowed by the firewall match the PPSM CLSA.  
 
If there are additional ports, protocols, or services that are not in the PPSM CLSA, or there are ports, protocols, or services that are prohibited by the PPSM CAL, this is a finding.'
  desc 'fix', "Update the host's firewall settings and/or running services to comply with the PPSM CLSA for the site or program and the PPSM CAL."
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52269r780069_chk'
  tag severity: 'medium'
  tag gid: 'V-248835'
  tag rid: 'SV-248835r780071_rule'
  tag stig_id: 'OL08-00-040030'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-52223r780070_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
