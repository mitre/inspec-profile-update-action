control 'SV-239850' do
  title 'The application server must use DoD- or CNSS-approved PKI Class 3 or Class 4 certificates.'
  desc 'Class 3 PKI certificates are used for servers and software signing rather than for identifying individuals. Class 4 certificates are used for business-to-business transactions. Utilizing unapproved certificates not issued or approved by DoD or CNS creates an integrity risk. The application server must utilize approved DoD or CNS Class 3 or Class 4 certificates for software signing and business-to-business transactions.'
  desc 'check', 'Verify that Smart Card Authentication is in use with the following steps:

1. In vRA, go to Administration >> Directories Management >> Identity Providers.
2. Verify that the identity provider listed is the identity provider used for smart card authentication.
3. In vRA, go to Administration >> Directories Management >> Policies.
4. Verify that the default policy authentication method is set to "certificate".

If the identity provider listed is not that used for smart card authentication, this is a finding.

If the default policy authentication method is not set to "certificate", this is a finding.'
  desc 'fix', 'Configure vRA to use Smart Card Authentication with the following steps:

1. Set up smart card infrastructure as per VMware documentation, if required.
2. In vRA, go to Administration >> Directories Management >> Identity Providers.
3. Add the identity provider used for smart card authentication.
4. In vRA, go to Administration >> Directories Management >> Policies.
5. Edit default policy and change authentication method to "certificate".'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Application'
  tag check_id: 'C-43083r664464_chk'
  tag severity: 'medium'
  tag gid: 'V-239850'
  tag rid: 'SV-239850r879885_rule'
  tag stig_id: 'VRAU-AP-000645'
  tag gtitle: 'SRG-APP-000514-AS-000137'
  tag fix_id: 'F-43042r664465_fix'
  tag 'documentable'
  tag legacy: ['SV-99785', 'V-89135']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
