control 'SV-254713' do
  title 'The BlackBerry Enterprise Mobility Server (BEMS) must remove all export ciphers to protect the confidentiality and integrity of transmitted information.'
  desc 'During the initial setup of a Transport Layer Security (TLS) connection to the application server, the client sends a list of supported cipher suites in order of preference. The application server will reply with the cipher suite it will use for communication from the client list. If an attacker can intercept the submission of cipher suites to the application server and place, as the preferred cipher suite, a weak export suite, the encryption used for the session becomes easy for the attacker to break, often within minutes to hours.'
  desc 'check', 'Verify BEMS has been configured to remove all export ciphers (automatically implemented when BEMS is in FIPS mode). Verify BEMS-03-014800 has been implemented.

If BEMS has been configured to use export ciphers, this is a finding.'
  desc 'fix', 'Configure BEMS to remove all export ciphers.

This requirement is met when BEMS is configured in FIPS mode. See BEMS-03-01480.'
  impact 0.5
  ref 'DPMS Target BlackBerry Enterprise Mobility Server 3.x'
  tag check_id: 'C-58324r861862_chk'
  tag severity: 'medium'
  tag gid: 'V-254713'
  tag rid: 'SV-254713r861864_rule'
  tag stig_id: 'BEMS-03-011500'
  tag gtitle: 'SRG-APP-000439-AS-000274'
  tag fix_id: 'F-58270r861863_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
