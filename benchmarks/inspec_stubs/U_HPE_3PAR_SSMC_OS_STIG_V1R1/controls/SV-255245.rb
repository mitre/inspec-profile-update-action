control 'SV-255245' do
  title 'For PKI-based authentication, SSMC must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.'
  desc 'Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted.

A trust anchor is an authoritative entity represented via a public key and associated data. It is used in the context of public key infrastructures, X.509 digital certificates, and DNSSEC.

When there is a chain of trust, usually the top entity to be trusted becomes the trust anchor; it can be, for example, a Certification Authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA.

This requirement verifies that a certification path to an accepted trust anchor is used for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement.'
  desc 'check', 'Check that the remote syslog connection is configured to use "x509/certvalid" or "x509/name" as authentication mode:

$ sudo /ssmc/bin/config_security.sh -o remote_syslog_appliance -a status | grep ssmc.rsyslog.server.authMode

Expected:
ssmc.rsyslog.server.authMode=x509/name
OR
ssmc.rsyslog.server.authMode=x509/certvalid

If the output does not match either of the expected strings, it is a finding.'
  desc 'fix', 'Configure SSMC to perform PKI-based authentication for remote syslog connectivity with "x509/certvalid" or "x509/name" setting for auth mode:

1. Log on to SSMC appliance as ssmcadmin. Press "X" to escape to general bash shell.

2. Use vi to edit and configure /ssmc/conf/security_config.properties file with values necessary to connect with a remote syslog server. 
ssmc.rsyslog.server.host=<rsyslog_server>
ssmc.rsyslog.server.port=<rsyslog_port>
ssmc.rsyslog.server.protocol=tcp
ssmc.rsyslog.server.tls-enabled=1
ssmc.rsyslog.cert.caroot=<ca_root_cert_pem>
ssmc.rsyslog.cert.clientcert=<ssmc_client_cert_pem>
ssmc.rsyslog.cert.clientkey=<ssmc_client_key_pem>
ssmc.rsyslog.server.authMode=< x509/name | x509/certvalid >
ssmc.rsyslog.server.permittedPeers=<cn_of_rsyslog_server>
ssmc.rsyslog.server.device=<ens160|ens192|eth0|eth1>
ssmc.rsyslog.queue.maxdiskspace=6

Save and exit.

3. Execute the following to activate connection to remote syslog server:
$ sudo /ssmc/bin/config_security.sh -o remote_syslog_server -a set -f'
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC OS'
  tag check_id: 'C-58858r869883_chk'
  tag severity: 'medium'
  tag gid: 'V-255245'
  tag rid: 'SV-255245r869885_rule'
  tag stig_id: 'SSMC-OS-010300'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-58802r869884_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
