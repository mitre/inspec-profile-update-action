control 'SV-222584' do
  title 'The application must only allow the use of DoD-approved certificate authorities for verification of the establishment of protected sessions.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.

The DoD will only accept PKI certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of SSL/TLS certificates.

This requirement focuses on communications protection for the application session rather than for the network packet.

This requirement applies to applications that utilize communications sessions. This includes, but is not limited to, web-based applications and Service-Oriented Architectures (SOA).'
  desc 'check', 'Review the application documentation and interview the application administrator to identify certificate location.

Internet Explorer can be used to view certificate information:

Select “Tools”
Select “Internet Options”
Select “Content” tab
Select “Certificates”
Select the certificate used for authentication:

Click “View”
Select “Details” tab
Select “Issuer”

If the application utilizes PKI certificates other than DoD-approved PKI and ECA certificates, this is a finding.'
  desc 'fix', 'Configure the application to utilize DoD-approved PKI established CAs when verifying DoD-signed certificates.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24254r493660_chk'
  tag severity: 'medium'
  tag gid: 'V-222584'
  tag rid: 'SV-222584r879798_rule'
  tag stig_id: 'APSC-DV-002300'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-24243r493661_fix'
  tag 'documentable'
  tag legacy: ['SV-84841', 'V-70219']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
