control 'SV-255254' do
  title 'SSMC web server must use cryptography to protect the integrity of remote sessions.'
  desc 'Data exchanged between the user and the web server can range from static display data to credentials used to Log on to the hosted application. Even when data appears to be static, the nondisplayed logic in a web page may expose business logic or trusted system relationships. The integrity of all data being exchanged between the user and web server must always be trusted. To protect the integrity and trust, encryption methods should be used to protect the complete communication session.'
  desc 'check', 'Verify that SSMC encrypts log exports to a remote syslog server with the following command: 

$ sudo /ssmc/bin/config_security.sh -o remote_syslog_appliance -a status | grep tls

ssmc.rsyslog.server.tls-enabled=1

If "ssmc.rsyslog.server.tls-enabled" does not equal "1", this is a finding.'
  desc 'fix', 'Configure SSMC to encrypt log exports to a remote syslog server:

1. Configure rsyslog parameters in /ssmc/conf/security_config.properties like below (use vi editor):
ssmc.rsyslog.server.tls-enabled=1

2. Execute "sudo /ssmc/bin/config_security.sh -o remote_syslog_appliance -a set -f" to commit the configuration and enable the service.'
  impact 0.7
  ref 'DPMS Target HPE 3PAR SSMC Web Server'
  tag check_id: 'C-58867r869929_chk'
  tag severity: 'high'
  tag gid: 'V-255254'
  tag rid: 'SV-255254r869931_rule'
  tag stig_id: 'SSMC-WS-010051'
  tag gtitle: 'SRG-APP-000015-WSR-000014'
  tag fix_id: 'F-58811r869930_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
