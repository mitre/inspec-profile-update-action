control 'SV-222398' do
  title 'Applications with SOAP messages requiring integrity must include the following message elements:-Message ID-Service Request-Timestamp-SAML Assertion (optionally included in messages) and all elements of the message must be digitally signed.'
  desc 'Digitally signed SOAP messages provide message integrity and authenticity of the signer of the message independent of the transport layer. Service requests may be intercepted and changed in transit and the data integrity may be at risk if the SOAP message is not digitally signed.

Functional architecture aspects of the application security plan identify the application data elements that require data integrity protection.'
  desc 'check', 'Review the application documentation, system security plan, application architecture diagrams and interview the application administrator.

Review the design document for web services using SOAP messages.

If the application does not utilize SOAP messages, this check is not applicable.

Review the design document and SOAP messages.
Verify the Message ID, Service Request, Timestamp, and SAML Assertion are included in the SOAP message.
If they are included, verify they are signed with a certificate.

If SOAP messages requiring integrity do not have the Message ID, Service Request, Timestamp, and SAML Assertion signed, or if any part of the message is not digitally signed, this is a finding.'
  desc 'fix', 'Design and configure the application to sign the following message elements for SOAP messages requiring integrity:

- Message ID
- Service Request
- Timestamp
- SAML Assertion
- Message elements'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24068r493102_chk'
  tag severity: 'medium'
  tag gid: 'V-222398'
  tag rid: 'SV-222398r508029_rule'
  tag stig_id: 'APSC-DV-000180'
  tag gtitle: 'SRG-APP-000015'
  tag fix_id: 'F-24057r493103_fix'
  tag 'documentable'
  tag legacy: ['SV-83883', 'V-69261']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
