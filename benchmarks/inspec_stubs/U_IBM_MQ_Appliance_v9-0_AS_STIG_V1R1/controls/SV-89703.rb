control 'SV-89703' do
  title 'The MQ Appliance messaging server must only allow the use of DoD PKI-established certificate authorities for verification of the establishment of protected (messaging) sessions.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.

The DoD will only accept PKI certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of SSL/TLS certificates.  The messaging server must only allow the use of DoD PKI-established certificate authorities for verification.'
  desc 'check', 'From the MQ Appliance WebGUI, click on the Administration (gear) icon.

Click on Main >> File Management.

Click on the cert directory.

Click on the "Details" action to the right of each cert to display its attributes.

Verify that each certificate attribute meets organizationally approved requirements.

If any certificates have not been issued by a DoD- or CNSS-approved PKI CA, this is a finding.'
  desc 'fix', 'Install certificates that have been issued by a DoD CA.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74881r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75029'
  tag rid: 'SV-89703r1_rule'
  tag stig_id: 'MQMH-AS-000790'
  tag gtitle: 'SRG-APP-000427-AS-000264'
  tag fix_id: 'F-81645r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
