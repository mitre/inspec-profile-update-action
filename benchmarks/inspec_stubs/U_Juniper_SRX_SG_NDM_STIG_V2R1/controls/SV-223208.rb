control 'SV-223208' do
  title 'The Juniper SRX Services Gateway must be configured to prohibit the use of unnecessary and/or nonsecure functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable unused or unnecessary physical and logical ports/protocols on information systems.

The control plane is responsible for operating most of the system services on the SRX. The control plane is responsible not only for acting as the interface for the administrator operating the device, but also for controlling the operation of the chassis, pushing the configuration to the data plane, and operating the daemons that provide functionality to the system. The control plane operates the Junos OS, which is a FreeBSD variant. 

The Juniper SRX control plane services include, but are not limited to, the following: Management Daemon (MGD), Routing Protocol Daemon (RPD) (e.g., RIP, OSPF, IS-IS, BGP, PIM, IPv6 counterparts), User interfaces (SSH, J-Web, NetConf), File system interfaces (SCP), Syslogd (DNS, DHCP, NTP, ICMP, ARP/ND, SNMP), Chassisd, JSRPD (HA clustering).'
  desc 'check', 'Entering the following commands from the configuration level of the hierarchy.

[edit]
show system services

If functions, ports, protocols, and services identified on the PPSM CAL are not disabled, this is a finding.'
  desc 'fix', 'Ensure functions, ports, protocols, and services identified on the PPSM CAL are not used for system services configuration.

[edit]
show system services

Compare the services that are enabled, including the port, services, protocols, and functions.

Consult the Juniper knowledge base and configuration guides to determine the commands for disabling each port, protocol, service, or function that is not in compliance with the PPSM CAL and vulnerability assessments.'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-24881r513311_chk'
  tag severity: 'medium'
  tag gid: 'V-223208'
  tag rid: 'SV-223208r513313_rule'
  tag stig_id: 'JUSX-DM-000108'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-24869r513312_fix'
  tag 'documentable'
  tag legacy: ['SV-80987', 'V-66497']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
