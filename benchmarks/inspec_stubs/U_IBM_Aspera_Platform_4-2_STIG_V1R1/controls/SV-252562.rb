control 'SV-252562' do
  title 'The IBM Aspera Console feature must be configured to use encryption services that implement NIST FIPS-validated cryptography to protect the confidentiality of remote access sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections. Remote access methods include, for example, proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies).

Encryption provides a means to secure the remote connection so as to prevent unauthorized access to the data traversing the remote access connection, thereby providing a degree of confidentiality. The encryption strength of the mechanism is selected based on the security categorization of the information.

This requirement applies to ALGs providing remote access proxy services as part of its intermediary services (e.g., OWA or TLS gateway).

For implementations using the IBM Aspera Console feature, the default configuration of Console has TLS 1.0 and 1.1 enabled to support older browsers.

'
  desc 'check', 'Verify IBM Aspera Console only uses TLS 1.2 or greater with the following command:

$ sudo grep SSLProtocol /opt/aspera/common/apache/conf/extra/httpd-ssl.conf
SSLProtocol TLSv1.2

If the values for SSLProtocol vary from the above example, this is a finding.'
  desc 'fix', 'Configure IBM Aspera Console to use TLS 1.2.

Add/Edit the following line in the Apache configuration file /opt/aspera/common/apache/conf/extra/httpd-ssl.conf.

SSLProtocol TLSv1.2

Restart Apache for these changes to take effect.

$ sudo /opt/aspera/common/asctl/asctl apache:restart'
  impact 0.7
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56018r817854_chk'
  tag severity: 'high'
  tag gid: 'V-252562'
  tag rid: 'SV-252562r817856_rule'
  tag stig_id: 'ASP4-CS-040150'
  tag gtitle: 'SRG-NET-000062-ALG-000011'
  tag fix_id: 'F-55968r817855_fix'
  tag satisfies: ['SRG-NET-000062-ALG-000011', 'SRG-NET-000400-ALG-000097']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000197']
  tag nist: ['AC-17 (2)', 'IA-5 (1) (c)']
end
