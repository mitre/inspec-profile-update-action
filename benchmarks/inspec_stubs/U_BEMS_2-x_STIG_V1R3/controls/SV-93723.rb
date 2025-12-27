control 'SV-93723' do
  title 'The BlackBerry Enterprise Mobility Server (BEMS) must remove all export ciphers to protect the confidentiality and integrity of transmitted information.'
  desc 'During the initial setup of a Transport Layer Security (TLS) connection to the application server, the client sends a list of supported cipher suites in order of preference. The application server will reply with the cipher suite it will use for communication from the client list. If an attacker can intercept the submission of cipher suites to the application server and place, as the preferred cipher suite, a weak export suite, the encryption used for the session becomes easy for the attacker to break, often within minutes to hours.'
  desc 'check', 'Verify BEMS has been configured to remove all export ciphers:

1. Find the xml file "jetty.xml" located in the BEMS install directory on the BEMS host Windows server. 
2. Find the "AllowCiphersSuites" field.
3. Verify if any export ciphers are listed in the "jetty.xml" file. Verify only approved cypher suites are included.  (See NIST SP 800-53r2 for a list of approved TLS suites.)

If BEMS has been configured to use export ciphers, this is a finding.'
  desc 'fix', 'Configure BEMS to remove all export ciphers.

1. Find the xml file "jetty.xml" located in the BEMS install directory on the BEMS host Windows server. 
2. Find the "AllowCiphersSuites" field and remove all cipher suites that are not approved. (See NIST SP 800-53r2 for a list of approved TLS suites.)
3. Save file.
4. Restart the BEMS server.'
  impact 0.5
  ref 'DPMS Target BEMS 2.x'
  tag check_id: 'C-78605r2_chk'
  tag severity: 'medium'
  tag gid: 'V-79017'
  tag rid: 'SV-93723r2_rule'
  tag stig_id: 'BEMS-00-011500'
  tag gtitle: 'SRG-APP-000439-AS-000274'
  tag fix_id: 'F-85767r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
