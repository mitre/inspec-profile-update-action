control 'SV-79477' do
  title 'The DBN-6300 must be compliant with at least one IETF Internet standard authentication protocol.'
  desc 'Protecting access authorization information (i.e., access control decisions) ensures that authorization information cannot be altered, spoofed, or otherwise compromised during transmission.

In distributed information systems, authorization processes and access control decisions may occur in separate parts of the systems. In such instances, authorization information is transmitted securely so timely access control decisions can be enforced at the appropriate locations. To support the access control decisions, it may be necessary to transmit, as part of the access authorization information, supporting security attributes. This is because, in distributed information systems, there are various access control decisions that need to be made, and different entities (e.g., services) make these decisions in a serial fashion, each requiring some security attributes to make the decisions.'
  desc 'check', 'Verify that the LDAP authentication server is configured correctly.

Navigate to Settings >> Initial Configuration >> Authentication.

Verify that the LDAP server entry is correct and the button for "LDAP Based Authentication" is enabled.

Verify that the "Native takes precedence" button is set to "Disabled".

If the LDAP server entry is not present and enabled, and the "Native takes precedence" button is not set to "Disabled", this is a finding.'
  desc 'fix', 'Navigate to Settings >> Initial Configuration >> Authentication.

Enter the correct LDAP server entry. 

Press the button for "LDAP Based Authentication" so that it is enabled.

If necessary, press the "Disabled" button for "Native takes precedence".

Press the "Commit" button.'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-65645r2_chk'
  tag severity: 'medium'
  tag gid: 'V-64987'
  tag rid: 'SV-79477r1_rule'
  tag stig_id: 'DBNW-DM-000089'
  tag gtitle: 'SRG-APP-000325-NDM-000285'
  tag fix_id: 'F-70927r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002353']
  tag nist: ['CM-6 b', 'AC-24 (1)']
end
