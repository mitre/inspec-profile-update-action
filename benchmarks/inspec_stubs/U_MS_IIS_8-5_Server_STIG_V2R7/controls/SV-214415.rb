control 'SV-214415' do
  title 'The IIS 8.5 web server must perform RFC 5280-compliant certification path validation.'
  desc 'This check verifies the server certificate is actually a DoD-issued certificate used by the organization being reviewed. This is used to verify the authenticity of the website to the user. If the certificate is not issued by the DoD or if the certificate has expired, then there is no assurance the use of the certificate is valid. The entire purpose of using a certificate is, therefore, compromised.'
  desc 'check', 'Open the IIS 8.5 Manager.
Click the IIS 8.5 web server name.
Double-click the "Server Certificate" icon.
Double-click each certificate and verify the certificate path is to a DoD root CA.
If the “Issued By” field of the PKI certificate being used by the IIS 8.5 server/site does not indicate the issuing Certificate Authority (CA) is part of the DoD PKI or an approved ECA, this is a finding.'
  desc 'fix', 'Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Double-click the "Server Certificate" icon.

Import a valid DoD certificate and remove any non-DoD certificates.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Server'
  tag check_id: 'C-15625r310293_chk'
  tag severity: 'medium'
  tag gid: 'V-214415'
  tag rid: 'SV-214415r879612_rule'
  tag stig_id: 'IISW-SV-000129'
  tag gtitle: 'SRG-APP-000175-WSR-000095'
  tag fix_id: 'F-15623r310294_fix'
  tag 'documentable'
  tag legacy: ['SV-91411', 'V-76715']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
