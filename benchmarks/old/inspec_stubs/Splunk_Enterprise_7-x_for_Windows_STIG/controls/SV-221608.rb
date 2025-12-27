control 'SV-221608' do
  title 'Splunk Enterprise must use SSL to protect the confidentiality and integrity of transmitted information.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered. 

This requirement applies only to those applications that are either distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications must leverage transmission protection mechanisms, such as TLS, SSL VPNs, or IPsec.

Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and this check will be N/A.'
  desc 'check', 'Execute a search query in Splunk using the following:

index=_internal source=*metrics.log* group=tcpin_connections | dedup hostname | table _time hostname sourceIp destPort ssl

Verify that the report returns ssl = true for every item listed.

If the report returns ssl = false for any item, this is a finding.'
  desc 'fix', 'Edit the following files in the installation to configure Splunk to use SSL certificates:

(Note that these files may exist in one of the following folders or its subfolders:
$SPLUNK_HOME/etc/apps/
$SPLUNK_HOME/etc/slave-apps/)

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
sslPassword = <password for the certificate>'
  impact 0.7
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23323r416281_chk'
  tag severity: 'high'
  tag gid: 'V-221608'
  tag rid: 'SV-221608r879810_rule'
  tag stig_id: 'SPLK-CL-000070'
  tag gtitle: 'SRG-APP-000439-AU-004310'
  tag fix_id: 'F-23312r416282_fix'
  tag 'documentable'
  tag legacy: ['SV-111317', 'V-102365']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
