control 'SV-79621' do
  title 'The DataPower Gateway must be compliant with at least one IETF standard authentication protocol.'
  desc 'Protecting access authorization information (i.e., access control decisions) ensures that authorization information cannot be altered, spoofed, or otherwise compromised during transmission.

In distributed information systems, authorization processes and access control decisions may occur in separate parts of the systems. In such instances, authorization information is transmitted securely so timely access control decisions can be enforced at the appropriate locations. To support the access control decisions, it may be necessary to transmit, as part of the access authorization information, supporting security attributes. This is because, in distributed information systems, there are various access control decisions that need to be made, and different entities (e.g., services) make these decisions in a serial fashion, each requiring some security attributes to make the decisions.'
  desc 'check', 'To verify that the secure transmission of authentication information has been configured, use the WebGUI to go to Objects >> XML Processing >> AAA Policy, select and existing AAA Policy.

Validate the authorization parameters on the Resource extraction, Resource mapping, and Authorization tabs. 

On the Authorization tab, confirm that all necessary parameters are properly configured for secure access to the authorization server. If they are not, this is a finding.'
  desc 'fix', 'The DataPower Gateway provides support for the secure transmission of authorization information to any supported authorization server. The following methods are supported: binarytokenx509, cleartrust, client-ssl, custom, kerberos, ldap, ltpa, netegrity, radius, saml-artifact, saml-authen-query, saml-signature, tivoli, token, validate-signer, ws-secureconversation, ws-trust, xmlfile, zosnss. 

To configure secure authorization, use the WebGUI to go to Objects >> XML Processing >> AAA Policy >> Press the "Add" button.

After completing the parameters for authentication (Main, Identity extraction, Authentication, and Credential Mapping tabs), complete the parameters for authorization (Resource extraction, Resource mapping, and Authorization tabs). 

DataPower provides secure access to all of the above-listed supported authorization methods. For example, on the AAA Policy Authorization tab described above, select "Check membership in LDAP group" as the authentication method. Parameters will then appear that allow the configuration of a secure SSL/TLS connection to that authorization server.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65759r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65131'
  tag rid: 'SV-79621r1_rule'
  tag stig_id: 'WSDP-NM-000087'
  tag gtitle: 'SRG-APP-000325-NDM-000285'
  tag fix_id: 'F-71071r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002353']
  tag nist: ['CM-6 b', 'AC-24 (1)']
end
