control 'SV-214328' do
  title 'The Apache web server must perform RFC 5280-compliant certification path validation.'
  desc "A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. Certification path validation includes checks such as certificate issuer trust, time validity, and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses."
  desc 'check', %q(Review the <'INSTALL PATH'>/conf/extra/httpd-ssl.conf file.

Look for the "SSLCACertificateFile" directive.

Review the path of the "SSLCACertificateFile" directive.

Review the contents of <'path of cert'>\ca-bundle.crt.

Examine the contents of this file to determine if the trusted CAs are DoD approved. If the trusted CA that is used to authenticate users to the website does not lead to an approved DoD CA, this is a finding.

NOTE: There are non-DoD roots that must be on the server for it to function. Some applications, such as antivirus programs, require root CAs to function. DoD-approved certificate can include the External Certificate Authorities (ECA), if approved by the AO. The PKE InstallRoot 3.06 System Administrator Guide (SAG), dated 08 Jul 2008, contains a complete list of DoD, ECA, and IECA CAs.)
  desc 'fix', "Configure the web server's trust store to trust only DoD-approved PKIs (e.g., DoD PKI, DoD ECA, and DoD-approved external partners).

Restart the Apache service."
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15540r277487_chk'
  tag severity: 'medium'
  tag gid: 'V-214328'
  tag rid: 'SV-214328r879612_rule'
  tag stig_id: 'AS24-W1-000380'
  tag gtitle: 'SRG-APP-000175-WSR-000095'
  tag fix_id: 'F-15538r277488_fix'
  tag 'documentable'
  tag legacy: ['SV-102481', 'V-92393']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
