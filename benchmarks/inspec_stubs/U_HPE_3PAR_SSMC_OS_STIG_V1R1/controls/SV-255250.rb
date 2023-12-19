control 'SV-255250' do
  title "SSMC must allocate audit record storage capacity to store at least one weeks' worth of audit records, when audit records are not immediately sent to a central audit record storage facility."
  desc 'In order to ensure operating systems have a sufficient storage capacity in which to write the audit logs, operating systems need to be able to allocate audit record storage capacity.

The task of allocating audit record storage capacity is usually performed during initial installation of the operating system.'
  desc 'check', %q(Verify SSMC allocates audit record storage capacity to store at least one weeks' worth of audit records, when audit records are not immediately sent to remote logging server by doing the following:

1. Log on to SSMC appliance as ssmcadmin. Press "X" to escape to general bash shell.

2. Execute the following command:

$ sudo /ssmc/bin/config_security.sh -o remote_syslog_appliance -a status | grep ssmc.rsyslog.queue.maxdiskspace

ssmc.rsyslog.queue.maxdiskspace=6

If the command output does not read "ssmc.rsyslog.queue.maxdiskspace=6", this is a finding.)
  desc 'fix', %q(Configure SSMC to allocate audit record storage capacity to store at least one week's worth of audit records. Perform the following to do so: 

1. Configure smtp parameters in /ssmc/conf/security_config.properties like below (use vi editor) -

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
ssmc.rsyslog.smtp.server=<server_ip>
ssmc.rsyslog.smtp.port=25
ssmc.rsyslog.smtp.recipient=["id1@domain","id2@domain"]
ssmc.rsyslog.smtp.notify-interval=300
ssmc.rsyslog.smtp.mailFrom=id@domain

2. Execute the following command to commit configuration and activate the service: 

$ sudo /ssmc/bin/config_security.sh -o remote_syslog_appliance -a set -f)
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC OS'
  tag check_id: 'C-58863r869898_chk'
  tag severity: 'medium'
  tag gid: 'V-255250'
  tag rid: 'SV-255250r869900_rule'
  tag stig_id: 'SSMC-OS-030140'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-58807r869899_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
