control 'SV-255258' do
  title 'The SSMC web server must be configured to use a specified IP address and port.'
  desc 'The web server must be configured to listen on a specified IP address and port. Without specifying an IP address and port for the web server to utilize, the web server will listen on all IP addresses available to the hosting server. If the web server has multiple IP addresses, i.e., a management IP address, the web server will also accept connections on the management IP address.

Accessing the hosted application through an IP address normally used for nonapplication functions opens the possibility of user access to resources, utilities, files, ports, and protocols that are protected on the desired application IP address.'
  desc 'check', 'Verify that SSMC web server is configured to listen on a specific network IP address, by doing the following:

1. Log on to ssmc appliance as ssmcadmin. Press "X" to escape to general bash shell.

2. Execute the command:

$ sudo /ssmc/bin/config_security.sh -o webserver_service_network -a status
Webserver service is listening on <ip_address>

If the command output does not display a specific IP address assigned to the SSMC host but reads "default IP address", this is a finding.'
  desc 'fix', 'Configure SSMC web server to listen on a specified network IP address by doing the following:

1. Log on to ssmc appliance as ssmcadmin; escape to general bash shell.

2. Edit (using vi editor) file /ssmc/conf/security_config.properties and set the property ssmc.webserver.service.network=<interface_name>

The property value can be any of ens160 or ens192 in an ESX environment; eth0 or eth1 in a Hyper-V environment.

3. Execute the command:

$ sudo /ssmc/bin/config_security.sh -o webserver_service_network -a set -f'
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC Web Server'
  tag check_id: 'C-58871r869941_chk'
  tag severity: 'medium'
  tag gid: 'V-255258'
  tag rid: 'SV-255258r869943_rule'
  tag stig_id: 'SSMC-WS-010090'
  tag gtitle: 'SRG-APP-000142-WSR-000089'
  tag fix_id: 'F-58815r869942_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
