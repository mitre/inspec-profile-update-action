control 'SV-32479' do
  title 'The private web server must use an approved DoD certificate validation process.'
  desc 'The Certificate Revocation List (CRL) is used for a number of reasons, for example, when an employee leaves, certificates expire, or if certificate keys become compromised and are reissued. Without the use of a certificate validation process, the server is vulnerable to accepting expired or revoked certificates. This could allow unauthorized individuals access to the web server. The CRL is a repository comprised of revoked certificate data, usually from many contributing CRL sources. 
Sites using an Online Certificate Status Protocol (OCSP) rather than CRL download to validate certificates will have obtained and installed an OCSP validation application.'
  desc 'check', 'Verify Certificate Revocation List (CRL) validation is enabled on the server.
Open a Command Prompt and enter the following command:

netsh http show sslcert

Note the value assigned to the Verify Client Certificate Revocation element. If the value of the Verify Client Certificate Revocation element is not enabled, this is a finding.'
  desc 'fix', 'Using vendor documentation as guidance, reconfigure the web server to utilize certificate with an approved certificate validation process:
netsh http add sslcert

Alternatively, configure existing certificate to validate certifcate revocation:

Open registry, locate HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters\\SslBindingInfo\\0.0.0.0:443\\DefaultSslCertCheckMode
Modify the value to 0
Restart server'
  impact 0.5
  ref 'DPMS Target IIS Installation 7'
  tag check_id: 'C-32794r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13672'
  tag rid: 'SV-32479r3_rule'
  tag stig_id: 'WG145 IIS7'
  tag gtitle: 'WG145'
  tag fix_id: 'F-29073r3_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
end
