control 'SV-99783' do
  title 'The application server must only allow the use of DoD PKI-established certificate authorities for verification of the establishment of protected sessions.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.

The DoD will only accept PKI certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of SSL/TLS certificates. The application server must only allow the use of DoD PKI-established certificate authorities for verification.'
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
  ref 'DPMS Target vRealize Automation 7.x Application'
  tag check_id: 'C-88825r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89133'
  tag rid: 'SV-99783r1_rule'
  tag stig_id: 'VRAU-AP-000540'
  tag gtitle: 'SRG-APP-000427-AS-000264'
  tag fix_id: 'F-95875r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
