control 'SV-255256' do
  title 'SSMC web server must generate information to be used by external applications or entities to monitor and control remote access.'
  desc 'Remote access to the web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions. 

By providing remote access information to an external monitoring system, the organization can monitor for cyber attacks and monitor compliance with remote access policies. The organization can also look at data organization wide and determine an attack or anomaly is occurring on the organization which might not be noticed if the data were kept local to the web server.

Examples of external applications used to monitor or control access would be audit log monitoring systems, dynamic firewalls, or infrastructure monitoring systems.'
  desc 'check', 'Verify that SSMC monitors remote access by doing the following:

1. Log on to SSH as ssmcadmin. Press "X" to escape to general bash shell.

2. Execute the following command to enable TCP access logs:

$ sudo /ssmc/bin/config_security.sh -o  tcp_access_log  -a status

TCP access logging is enabled

If the command output does not read "TCP access logging is enabled", this is a finding.'
  desc 'fix', 'Configure SSMC to be monitored for remote access by doing the following:

1. Log on to SSH as ssmcadmin. Press "X" to escape to general bash shell.

2. Execute the following command to enable TCP access logs:

$ sudo /ssmc/bin/config_security.sh -o tcp_access_log -a enable -f'
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC Web Server'
  tag check_id: 'C-58869r869935_chk'
  tag severity: 'medium'
  tag gid: 'V-255256'
  tag rid: 'SV-255256r879521_rule'
  tag stig_id: 'SSMC-WS-010070'
  tag gtitle: 'SRG-APP-000016-WSR-000005'
  tag fix_id: 'F-58813r869936_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
