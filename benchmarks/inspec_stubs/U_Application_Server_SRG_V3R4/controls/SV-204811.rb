control 'SV-204811' do
  title 'The application server must only allow the use of DoD PKI-established certificate authorities for verification of the establishment of protected sessions.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.

The DoD will only accept PKI certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of SSL/TLS certificates.  The application server must only allow the use of DoD PKI-established certificate authorities for verification.'
  desc 'check', 'Review the application server documentation and configuration to determine if the application server only allows the use of DoD PKI-established certificate authorities.

If the application server allows other certificate authorities for verification, this is a finding.'
  desc 'fix', 'Configure the application server to allow the use of DoD PKI-established certificate authorities for verification of the establishment of protected sessions.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4931r283074_chk'
  tag severity: 'medium'
  tag gid: 'V-204811'
  tag rid: 'SV-204811r879798_rule'
  tag stig_id: 'SRG-APP-000427-AS-000264'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-4931r283075_fix'
  tag 'documentable'
  tag legacy: ['SV-71827', 'V-57551']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
