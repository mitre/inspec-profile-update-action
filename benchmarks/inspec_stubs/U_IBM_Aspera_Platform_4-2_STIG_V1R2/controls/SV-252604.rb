control 'SV-252604' do
  title 'The IBM Aspera Shares feature must be configured to use encryption services that implement NIST FIPS-validated cryptography to protect the confidentiality of remote access sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections. Remote access methods include, for example, proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies).

Encryption provides a means to secure the remote connection so as to prevent unauthorized access to the data traversing the remote access connection, thereby providing a degree of confidentiality. The encryption strength of the mechanism is selected based on the security categorization of the information.

This requirement applies to ALGs providing remote access proxy services as part of its intermediary services (e.g., OWA or TLS gateway).

For implementations using the IBM Aspera Shares feature, the default nginx configuration of Shares has TLS 1.0, 1.1 and 1.2 enabled to support older browsers.

'
  desc 'check', 'If the IBM Aspera Shares feature of the Aspera Platform is not installed, this is Not Applicable.

Verify IBM Aspera Shares only uses TLS 1.2 or greater with the following command:

$ sudo grep ssl_protocols /opt/aspera/shares/etc/nginx/nginx.conf
 ssl_protocols TLSv1.2;

If the results of the command display versions below "TLSv1.2", this is a finding.'
  desc 'fix', 'Configure IBM Aspera Shares to use TLS 1.2.

Add/Edit the following line in the nginx.conf file located at /opt/aspera/shares/etc/nginx/nginx.conf. 

ssl_protocols TLSv1.2; 

Restart nginx for these changes to take effect.

$ sudo /opt/aspera/shares/sbin/sv restart nginix'
  impact 0.7
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56060r817980_chk'
  tag severity: 'high'
  tag gid: 'V-252604'
  tag rid: 'SV-252604r817982_rule'
  tag stig_id: 'ASP4-SH-060170'
  tag gtitle: 'SRG-NET-000062-ALG-000011'
  tag fix_id: 'F-56010r817981_fix'
  tag satisfies: ['SRG-NET-000062-ALG-000011', 'SRG-NET-000400-ALG-000097']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000197']
  tag nist: ['AC-17 (2)', 'IA-5 (1) (c)']
end
