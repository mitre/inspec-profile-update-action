control 'SV-218800' do
  title 'The IIS 10.0 web server must perform RFC 5280-compliant certification path validation.'
  desc 'This check verifies the server certificate is actually a DoD-issued certificate used by the organization being reviewed. This is used to verify the authenticity of the website to the user. If the certificate is not issued by the DoD or if the certificate has expired, then there is no assurance the use of the certificate is valid, and therefore; the entire purpose of using a certificate is compromised.'
  desc 'check', 'Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Double-click the "Server Certificate" icon.

Double-click each certificate and verify the certificate path is to a DoD root CA.

If the “Issued By” field of the PKI certificate being used by the IIS 10.0 server/site does not indicate the issuing Certificate Authority (CA) is part of the DoD PKI or an approved ECA, this is a finding.'
  desc 'fix', 'Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Double-click the "Server Certificate" icon.

Import a valid DoD certificate and remove any non-DoD certificates.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-20272r310875_chk'
  tag severity: 'medium'
  tag gid: 'V-218800'
  tag rid: 'SV-218800r879612_rule'
  tag stig_id: 'IIST-SV-000129'
  tag gtitle: 'SRG-APP-000175-WSR-000095'
  tag fix_id: 'F-20270r310876_fix'
  tag 'documentable'
  tag legacy: ['SV-109239', 'V-100135']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
