control 'SV-221932' do
  title 'Splunk Enterprise must only allow the use of DoD-approved certificate authorities for cryptographic functions.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.

The DoD will only accept PKI certificates obtained from a DoD-approved internal or external certificate authority. 

Splunk Enterprise contains built-in certificates that are common across all Splunk installations and are for initial deployment. These should not be used in any production environment.

The production certificates should be stored in another location away from the Splunk default certificates, as that folder is replaced on any upgrade of the application.

An example would be to use a folder named $SPLUNK_HOME/etc/system/DoDcerts under the Splunk installation root folder.'
  desc 'check', 'Verify the properties of the certificates used by Splunk to ensure that the Issuer is the DoD trusted CA.

Check the following files for the certificates in use by Splunk.

This file is located on the machine used as the search head, which may be a separate machine in a distributed environment.

$SPLUNK_HOME/etc/system/local/web.conf

[settings]
serverCert = <path to the DoD approved certificate in PEM format>

This file is located on the machine used as an indexer, which may be a separate machine in a distributed environment.

$SPLUNK_HOME/etc/system/local/inputs.conf

[SSL]
serverCert = <path to the DoD approved certificate in PEM format>

This file is located on the machine used as a forwarder, which is always a separate machine regardless of environment.

$SPLUNK_HOME/etc/system/local/outputs.conf

[tcpout:group1]
clientCert = <path to the DoD approved certificate in PEM format>

Verify each certificate listed above with the following command:

openssl x509 -text -inform PEM -in <name of cert>

If the certificate issuer is not a DoD trusted CA, this is a finding.'
  desc 'fix', 'Request a DoD-approved certificate and a copy of the DoD root CA public certificate and place the files in a location for Splunk use.

Configure the certificate files to the PEM format using the Splunk Enterprise system documentation.'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23646r420264_chk'
  tag severity: 'medium'
  tag gid: 'V-221932'
  tag rid: 'SV-221932r879798_rule'
  tag stig_id: 'SPLK-CL-000040'
  tag gtitle: 'SRG-APP-000427-AU-000040'
  tag fix_id: 'F-23635r420265_fix'
  tag 'documentable'
  tag legacy: ['SV-111363', 'V-102419']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
