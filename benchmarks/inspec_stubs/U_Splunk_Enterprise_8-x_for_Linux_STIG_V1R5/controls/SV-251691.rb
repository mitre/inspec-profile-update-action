control 'SV-251691' do
  title 'Splunk Enterprise must be configured to protect the confidentiality and integrity of transmitted information.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered. 

This requirement applies only to those applications that are either distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications need to leverage transmission protection mechanisms, such as TLS, SSL VPNs, or IPsec.

Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.'
  desc 'check', 'Check the following files in the installation to verify Splunk uses SSL certificates for communication between the indexer and the forwarder:

This check is performed on the machine used as an indexer, which may be a separate machine in a distributed environment.

$SPLUNK_HOME/etc/system/local/inputs.conf

[splunktcp-ssl:9997]
disabled = 0

[SSL]
serverCert = <path to the DoD approved certificate in PEM format>
sslPassword = <password for the certificate>

If these settings are misconfigured, this is a finding.

This configuration is performed on the machine used as a forwarder, which is always a separate machine regardless of environment.

$SPLUNK_HOME/etc/system/local/outputs.conf

[tcpout:group1]
disabled = 0
clientCert = <path to the DoD approved certificate in PEM format>
sslPassword = <password for the certificate>

If these settings are misconfigured, this is a finding.'
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
sslPassword = <password for the certificate>'
  impact 0.7
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55129r819131_chk'
  tag severity: 'high'
  tag gid: 'V-251691'
  tag rid: 'SV-251691r879810_rule'
  tag stig_id: 'SPLK-CL-000460'
  tag gtitle: 'SRG-APP-000439-AU-004310'
  tag fix_id: 'F-55083r819132_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
