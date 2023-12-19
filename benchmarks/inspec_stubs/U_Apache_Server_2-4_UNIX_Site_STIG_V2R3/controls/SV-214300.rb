control 'SV-214300' do
  title 'The Apache web server must only accept client certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs).'
  desc 'Non-DoD approved PKIs have not been evaluated to ensure that they have security controls and identity vetting procedures in place that are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users.'
  desc 'check', %q(Verify the “ssl module” module is loaded
# httpd -M | grep -i ssl_module
Output:  ssl_module (shared) 

If the "ssl_module" is not found, this is a finding. 

Determine the location of the ssl.conf file:
# find / -name ssl.conf
Output: /etc/httpd/conf.d/ssl.conf

Search the ssl.conf file for the 
# cat /etc/httpd/conf.d/ssl.conf | grep -i "SSLCACertificateFile"
Output should be similar to: SSLCACertificateFile /etc/pki/tls/certs/ca-bundle.crt

Review the path of the "SSLCACertificateFile" directive.

Review the contents of <'path of SSLCACertificateFile'>\ca-bundle.crt.

Examine the contents of this file to determine if the trusted CAs are DoD approved.

If the trusted CA that is used to authenticate users to the website does not lead to an approved DoD CA, this is a finding.

NOTE: There are non-DoD roots that must be on the server for it to function. Some applications, such as antivirus programs, require root CAs to function. DoD-approved certificate can include the External Certificate Authorities (ECA) if approved by the AO. The PKE InstallRoot 3.06 System Administrator Guide (SAG), dated 08 Jul 2008, contains a complete list of DoD, ECA, and IECA CAs.)
  desc 'fix', 'Configure the web server’s trust store to trust only DoD-approved PKIs (e.g., DoD PKI, DoD ECA, and DoD-approved external partners).'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Site'
  tag check_id: 'C-15513r881512_chk'
  tag severity: 'medium'
  tag gid: 'V-214300'
  tag rid: 'SV-214300r881513_rule'
  tag stig_id: 'AS24-U2-000810'
  tag gtitle: 'SRG-APP-000427-WSR-000186'
  tag fix_id: 'F-15511r277242_fix'
  tag 'documentable'
  tag legacy: ['SV-102909', 'V-92821']
  tag cci: ['CCI-002500']
  tag nist: ['SC-31 (2)']
end
