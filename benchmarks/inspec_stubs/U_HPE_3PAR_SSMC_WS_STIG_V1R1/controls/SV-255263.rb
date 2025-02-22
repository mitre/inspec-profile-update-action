control 'SV-255263' do
  title 'SSMC web server must restrict connections from nonsecure zones.'
  desc 'Remote access to the web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions.

A web server can be accessed remotely and must be capable of restricting access from what the DOD defines as nonsecure zones. Nonsecure zones are defined as any IP, subnet, or region that is defined as a threat to the organization. The nonsecure zones must be defined for public web servers logically located in a DMZ, as well as private web servers with perimeter protection devices. By restricting access from nonsecure zones, through internal web server access list, the web server can stop or slow denial of service (DoS) attacks on the web server.

'
  desc 'check', 'Verify that SSMC is configured to block DOD-defined nonsecure zones  using remote host access controls by doing the following:

1. Log on to SSMC appliance as ssmcadmin. Press "X" to escape to general bash shell.

2. Execute the following command: 

$ sudo /ssmc/bin/config_security.sh -o host_access -a status

Host access is configured

If the command output does not read "Host access is configured", this is a finding.

3. Review the inbound and outbound allow lists by executing the following command:

$ grep ^ssmc.*.hosts.allow /ssmc/conf/security_config.properties

ssmc.inbound.hosts.allow=<comma separated list or range of hosts>

ssmc.outbound.hosts.allow=<comma separated list or range of hosts>

If the inbound and outbound allow lists do not restrict connections from nonsecure zones, this is a finding.'
  desc 'fix', 'Configure SSMC to block access from DOD-defined nonsecure zones by enabling remote host access control by doing the following:

1. Log on to SSMC appliance as ssmcadmin. Press "X" to escape to general bash shell.

2. Configure all hosts to which network traffic needs to be allowed by setting these two properties in /ssmc/conf/security_config.properties.

ssmc.inbound.hosts.allow=<comma separated list or range of hosts; cidr and range notations are supported>

ssmc.outbound.hosts.allow=<comma separated list or range of hosts; cidr and range notations are supported>

3. Execute the following command: 

$ sudo /ssmc/bin/config_security.sh -o host_access -a set'
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC Web Server'
  tag check_id: 'C-58876r870276_chk'
  tag severity: 'medium'
  tag gid: 'V-255263'
  tag rid: 'SV-255263r870278_rule'
  tag stig_id: 'SSMC-WS-010180'
  tag gtitle: 'SRG-APP-000315-WSR-000004'
  tag fix_id: 'F-58820r870277_fix'
  tag satisfies: ['SRG-APP-000315-WSR-000004', 'SRG-APP-000315-WSR-000003']
  tag 'documentable'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
