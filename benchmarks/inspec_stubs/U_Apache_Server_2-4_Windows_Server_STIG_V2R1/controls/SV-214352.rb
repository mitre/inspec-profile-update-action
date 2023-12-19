control 'SV-214352' do
  title 'The Apache web server must only accept client certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs).'
  desc 'Non-DoD-approved PKIs have not been evaluated to ensure they have security controls and identity vetting procedures in place that are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users.'
  desc 'check', %q(Review the "ssl.conf" file.

Look for the "SSLCACertificateFile" directive.

Review the path of the "SSLCACertificateFile" directive.

Review the contents of <'path of cert'>\ca-bundle.crt.

Examine the contents of this file to determine if the trusted CAs are DoD approved.

If the trusted CA that is used to authenticate users to the website does not lead to an approved DoD CA, this is a finding.

NOTE: There are non-DoD roots that must be on the server for it to function. Some applications, such as antivirus programs, require root CAs to function. DoD-approved certificate can include the External Certificate Authorities (ECA), if approved by the AO. The PKE InstallRoot 3.06 System Administrator Guide (SAG), dated 08 Jul 2008, contains a complete list of DoD, ECA, and IECA CAs.)
  desc 'fix', "Configure the web server's trust store to trust only DoD-approved PKIs (e.g., DoD PKI, DoD ECA, and DoD-approved external partners)."
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15564r277559_chk'
  tag severity: 'medium'
  tag gid: 'V-214352'
  tag rid: 'SV-214352r505936_rule'
  tag stig_id: 'AS24-W1-000800'
  tag gtitle: 'SRG-APP-000427-WSR-000186'
  tag fix_id: 'F-15562r277560_fix'
  tag 'documentable'
  tag legacy: ['V-92845', 'SV-102933']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
