control 'SV-32936' do
  title 'A private web server’s list of CAs in a trust hierarchy must lead to an authorized  DoD PKI Root CA.'
  desc 'A PKI certificate is a digital identifier that establishes the identity of an individual or a platform. A server that has a certificate provides users with third-party confirmation of authenticity. Most web browsers perform server authentication automatically and the user is notified only if the authentication fails. The authentication process between the server and the client is performed using the SSL/TLS protocol. Digital certificates are authenticated, issued, and managed by a trusted Certificate Authority (CA).

The use of a trusted certificate validation hierarchy is crucial to the ability to control access to a site’s server and to prevent unauthorized access. Only DoD-approved PKIs will be utilized.'
  desc 'check', 'Enter the following command: 

find / -name ssl.conf  note the path of the file. 

grep "SSLCACertificateFile" /path/of/ssl.conf  

Review the results to determine the path of the SSLCACertificateFile. 

more /path/of/ca-bundle.crt 

Examine the contents of this file to determine if the trusted CAs are DoD approved. If the trusted CA that is used to authenticate users to the web site does not lead to an approved DoD CA, this is a finding. 

NOTE: There are non DoD roots that must be on the server in order for it to function. Some applications, such as anti-virus programs, require root CAs to function. DoD approved certificate can include the External Certificate Authorities (ECA), if approved by the DAA. The PKE InstallRoot 3.06 System Administrator Guide (SAG), dated 8 Jul 2008, contains a complete list of DoD, ECA, and IECA CAs.'
  desc 'fix', 'Configure the web server’s trust store to trust only DoD-approved PKIs (e.g., DoD PKI, DoD ECA, and DoD-approved external partners).'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33628r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13620'
  tag rid: 'SV-32936r1_rule'
  tag stig_id: 'WG355 A22'
  tag gtitle: 'WG355'
  tag fix_id: 'F-29265r1_fix'
  tag 'documentable'
  tag responsibility: ['Web Administrator', 'Information Assurance Officer']
  tag ia_controls: 'IATS-1, IATS-2'
end
