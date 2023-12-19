control 'SV-229001' do
  title 'The BIG-IP appliance must be configured to transmit access authorization information using approved security safeguards to authorized information systems that enforce access control decisions.'
  desc 'Protecting access authorization information (i.e., access control decisions) ensures that authorization information cannot be altered, spoofed, or otherwise compromised during transmission.

In distributed information systems, authorization processes and access control decisions may occur in separate parts of the systems. In such instances, authorization information is transmitted securely so timely access control decisions can be enforced at the appropriate locations. To support the access control decisions, it may be necessary to transmit, as part of the access authorization information, supporting security attributes. This is because, in distributed information systems, there are various access control decisions that need to be made, and different entities (e.g., services) make these decisions in a serial fashion, each requiring some security attributes to make the decisions.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a properly configured authentication server that transmits access authorization information using approved security safeguards to authorized information systems that enforce access control decisions.

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify that "User Directory" is set to an approved authentication server and SSL is set to use TLS.

If the BIG-IP appliance transmits access authorization information without using approved security safeguards to authorized information systems that enforce access control decisions, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use a properly configured authentication server that transmits access authorization information using approved security safeguards to authorized information systems that enforce access control decisions.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31316r518048_chk'
  tag severity: 'medium'
  tag gid: 'V-229001'
  tag rid: 'SV-229001r879887_rule'
  tag stig_id: 'F5BI-DM-000175'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31293r518049_fix'
  tag 'documentable'
  tag legacy: ['SV-74621', 'V-60191']
  tag cci: ['CCI-000366', 'CCI-002353']
  tag nist: ['CM-6 b', 'AC-24 (1)']
end
