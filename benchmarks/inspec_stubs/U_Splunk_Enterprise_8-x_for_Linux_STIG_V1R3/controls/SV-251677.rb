control 'SV-251677' do
  title 'Analysis, viewing, and indexing functions, services, and applications used as part of Splunk Enterprise must be configured to comply with DoD-trusted path and access requirements.'
  desc 'Access to Splunk Enterprise for analysis, viewing, indexing functions, services, and applications, such as analysis tools and other vendor-provided applications, must be secured. Software used to perform additional functions, which resides on the server, must also be secured or could provide a vector for unauthorized access to the events repository.'
  desc 'check', 'Execute a search query in Splunk using the following:

index=_internal source=*metrics.log* group=tcpin_connections | dedup hostname | table _time hostname sourceIp destPort ssl

Verify that the report returns ssl = true for every item listed.

Navigate to $SPLUNK_HOME/etc/system/local/web.conf and verify the enableSplunkWebSSL is set to 1.

If the report returns ssl = false for any item, and/or If enableSplunkWebSSL is not set, this is a finding.'
  desc 'fix', 'Edit the following files in the installation to configure Splunk to use SSL certificates:

This configuration is performed on the machine used as an indexer, which may be a separate machine in a distributed environment.

$SPLUNK_HOME/etc/system/local/inputs.conf

[splunktcp-ssl:9997]
disabled = 0

[SSL]
serverCert = <path to the DoD approved certificate in PEM format>
sslPassword = <password for the certificate>

This configuration is performed on the machine used as a forwarder, which is always a separate machine regardless of environment.

$SPLUNK_HOME/etc/system/local/outputs.conf

[tcpout:group1]
disabled = 0
clientCert = <path to the DoD approved certificate in PEM format>
sslPassword = <password for the certificate>

This configuration is performed on the machine used as a search head, which may be a separate machine in a distributed environment.

Edit the following file in the installation to configure Splunk to use SSL certificates:

$SPLUNK_HOME/etc/opt/system/local/web.conf

[settings]
enableSplunkWebSSL = 1
privKeyPath = <path to the private key generated for the DoD approved certificate>
serverCert = <path to the DoD approved certificate in PEM format>'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55115r819098_chk'
  tag severity: 'medium'
  tag gid: 'V-251677'
  tag rid: 'SV-251677r835285_rule'
  tag stig_id: 'SPLK-CL-000290'
  tag gtitle: 'SRG-APP-000516-AU-000410'
  tag fix_id: 'F-55069r835284_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
