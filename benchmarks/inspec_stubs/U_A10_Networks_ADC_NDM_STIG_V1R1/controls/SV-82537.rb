control 'SV-82537' do
  title 'The A10 Networks ADC must disable management protocol access to all interfaces except the management interface.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable unused or unnecessary physical and logical ports/protocols on information systems.

Network devices are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the network device must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', %q(Review the device configuration.

The following command displays the types of management access allowed on each of the device's interfaces:
show management

If SSH, Telnet, HTTP, HTTPS, or SNMP is "on" for any of the interfaces other than the management interface, this is a finding.

Note: Ping may be used on inward-facing interfaces.)
  desc 'fix', 'The following command disables ping, SSH, Telnet, HTTP, HTTPS, and SNMP to a range of interfaces:
no enable-management service all ethernet [number] to [number]

Note: Ping may be used on inward-facing interfaces.'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68607r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68047'
  tag rid: 'SV-82537r1_rule'
  tag stig_id: 'AADC-NM-000046'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-74163r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
