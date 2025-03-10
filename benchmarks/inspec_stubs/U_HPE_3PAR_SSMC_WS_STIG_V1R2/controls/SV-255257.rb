control 'SV-255257' do
  title 'SSMC web server must generate information to be used by external applications or entities to monitor and control remote access.'
  desc 'Remote access to the web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions. 

By providing remote access information to an external monitoring system, the organization can monitor for cyber attacks and monitor compliance with remote access policies. The organization can also look at data organization wide and determine an attack or anomaly is occurring on the organization which might not be noticed if the data were kept local to the web server.

Examples of external applications used to monitor or control access would be audit log monitoring systems, dynamic firewalls, or infrastructure monitoring systems.

'
  desc 'check', 'Verify that SSMC monitors remote access by enabling exports to a remote syslog server with the following command: 

$ sudo /ssmc/bin/config_security.sh -o remote_syslog_appliance -a status | sed 1q

Remote syslog service status is OK

If the output does not read "Remote syslog service status is OK", this is a finding.'
  desc 'fix', 'Configure SSMC to be monitored for remote access by enabling exports to a remote syslog server:

1. Configure rsyslog parameters in /ssmc/conf/security_config.properties like below (use vi editor):

ssmc.rsyslog.server.host=<rsyslog_server>
ssmc.rsyslog.server.port=<rsyslog_port>
ssmc.rsyslog.server.protocol=tcp
ssmc.rsyslog.server.tls-enabled=1
ssmc.rsyslog.cert.caroot=<ca_root_cert_pem>
ssmc.rsyslog.cert.clientcert=<ssmc_client_cert_pem>
ssmc.rsyslog.cert.clientkey=<ssmc_client_key_pem>
ssmc.rsyslog.server.authMode=<x509/name | x509/certvalid>
ssmc.rsyslog.server.permittedPeers=<cn_of_rsyslog_server>
ssmc.rsyslog.server.device=<ens160|ens192|eth0|eth1>
ssmc.rsyslog.queue.maxdiskspace=6
ssmc.rsyslog.smtp.alert=true
ssmc.rsyslog.smtp.server=<smtp_server_ip>
ssmc.rsyslog.smtp.port=<smtp_port>
ssmc.rsyslog.smtp.recipient=["id1@domain","id2@domain"]
ssmc.rsyslog.smtp.notify-interval=300
ssmc.rsyslog.smtp.mailFrom=id@domain

2. Execute "sudo /ssmc/bin/config_security.sh -o remote_syslog_appliance -a set -f" to commit the configuration and enable the service.'
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC Web Server'
  tag check_id: 'C-58870r869938_chk'
  tag severity: 'medium'
  tag gid: 'V-255257'
  tag rid: 'SV-255257r879521_rule'
  tag stig_id: 'SSMC-WS-010080'
  tag gtitle: 'SRG-APP-000016-WSR-000005'
  tag fix_id: 'F-58814r869939_fix'
  tag satisfies: ['SRG-APP-000016-WSR-000005', 'SRG-APP-000358-WSR-000163', 'SRG-APP-000358-WSR-000063', 'SRG-APP-000125-WSR-000071']
  tag 'documentable'
  tag cci: ['CCI-000067', 'CCI-001348', 'CCI-001851']
  tag nist: ['AC-17 (1)', 'AU-9 (2)', 'AU-4 (1)']
end
