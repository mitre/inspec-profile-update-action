control 'SV-86165' do
  title 'The CA API Gateway must transmit organization-defined access authorization information using organization-defined security safeguards to organization-defined information systems which enforce access control decisions.'
  desc 'Protecting access authorization information (i.e., access control decisions) ensures that authorization information cannot be altered, spoofed, or otherwise compromised during transmission.

In distributed information systems, authorization processes and access control decisions may occur in separate parts of the systems. In such instances, authorization information is transmitted securely so timely access control decisions can be enforced at the appropriate locations. To support the access control decisions, it may be necessary to transmit, as part of the access authorization information, supporting security attributes. This is because, in distributed information systems, there are various access control decisions that need to be made, and different entities (e.g., services) make these decisions in a serial fashion, each requiring some security attributes to make the decisions.'
  desc 'check', 'Verify the CA API Gateway is configured to use LDAP or RADIUS+LDAP for all administrative accounts by using the "ssgconfig" account and using menu: 1) Configure system settings >> 4) Configure authentication method.

Select the appropriate ldap/ldap+radius configuration and then verify its settings by continuing the menu process until it completes.

If LDAP or RADIUS+LDAP is not configured for all administrative accounts, this is a finding.'
  desc 'fix', 'Configure the Gateway to use LDAP or RADIUS+LDAP for all administrative accounts by using the "ssgconfig" account and using menu: 1) Configure system settings >> 4) Configure authentication method.

Select the appropriate ldap/ldap+radius configuration and then set the appropriate settings for your environment by following the menu process until it completes.'
  impact 0.5
  ref 'DPMS Target CA API Gateway NDM'
  tag check_id: 'C-71913r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71541'
  tag rid: 'SV-86165r1_rule'
  tag stig_id: 'CAGW-DM-000210'
  tag gtitle: 'SRG-APP-000325-NDM-000285'
  tag fix_id: 'F-77861r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002353']
  tag nist: ['CM-6 b', 'AC-24 (1)']
end
