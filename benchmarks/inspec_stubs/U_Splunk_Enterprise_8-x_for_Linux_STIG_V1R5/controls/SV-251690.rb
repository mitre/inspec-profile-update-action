control 'SV-251690' do
  title 'Splunk Enterprise must only allow the use of DoD-approved certificate authorities for cryptographic functions.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.

The DoD will only accept PKI certificates obtained from a DoD-approved internal or external certificate authority. 

Splunk Enterprise contains built-in certificates that are common across all Splunk installations, and are for initial deployment. These should not be used in any production environment.

It is also recommended that the production certificates be stored in another location away from the Splunk default certificates, as that folder gets replaced on any upgrade of the application. An example would be to use a folder named /etc/system/DoDcerts under the Splunk installation root folder.'
  desc 'check', 'On the host OS of the server, verify the properties of the certificate used by Splunk to ensure that the Issuer is the DoD trusted CA.

This can be verified by the command:

openssl x509 -text -inform PEM -in <name of cert>

If the certificate issuer is not a DoD trusted CA, then this is a finding.'
  desc 'fix', 'Request a DoD-approved certificate and a copy of the DoD root CA public certificate, and place the files in a location for Splunk use.

Configure the certificate files to the PEM format, using the Splunk Enterprise system documentation.'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55128r808304_chk'
  tag severity: 'medium'
  tag gid: 'V-251690'
  tag rid: 'SV-251690r879798_rule'
  tag stig_id: 'SPLK-CL-000450'
  tag gtitle: 'SRG-APP-000427-AU-000040'
  tag fix_id: 'F-55082r808305_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
