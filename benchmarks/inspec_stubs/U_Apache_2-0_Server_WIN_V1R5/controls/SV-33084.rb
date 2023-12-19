control 'SV-33084' do
  title 'A private web server’s list of CAs in a trust hierarchy must lead to an authorized DoD PKI Root CA.'
  desc 'A PKI certificate is a digital identifier that establishes the identity of an individual or a platform. A server that has a certificate provides users with third-party confirmation of authenticity. Most web browsers perform server authentication automatically; the user is notified only if the authentication fails. The authentication process between the server and the client is performed using the SSL/TLS protocol. Digital certificates are authenticated, issued, and managed by a trusted Certification Authority (CA). 

The use of a trusted certificate validation hierarchy is crucial to the ability to control access to your server and prevent unauthorized access. This hierarchy needs to lead to the DoD PKI Root CA or to an approved External Certificate Authority (ECA) or are required for the server to function.'
  desc 'check', 'The reviewer will need to have the SA or Web Manager show the list of CA’s the server is trusting to authenticate users.

NOTE: There are non DoD roots that must be on the server in order for it to function. Some applications, such as anti-virus programs, require root CAs to function.

The location for the conf file that controls the SSL parameters may vary from installation, so the following is just an example of a default httpd-ssl.conf file.

Open httpd-ssl.conf and search for the following directive:

SSLCACertificateFile

This directive will point to the file that contains the certificates that are used to identify the CAs that are used for client authentication. Such a file is simply the concatenation of the various PEM-encoded Certificate files, in order of preference. Examine the contents of this file to determine if the trusted CAs are DoD approved. 

DoD approved can include the External Certificate Authorities (ECA), if approved by the DAA. The PKE InstallRoot 3.06 System Administrator Guide (SAG), dated 8 Jul 2008, contains a complete list of DoD, ECA, and IECA CAs. If the trusted CAs that are used to authenticate users to the web site does not lead to an approved DoD CA, this is a finding.'
  desc 'fix', 'Configure the web server’s trust store to trust only DoD-approved PKIs (e.g., DoD PKI, DoD ECA, and DoD-approved external partners).'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33755r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13620'
  tag rid: 'SV-33084r1_rule'
  tag stig_id: 'WG355 W22'
  tag gtitle: 'WG355'
  tag fix_id: 'F-29391r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'IATS-1, IATS-2'
end
