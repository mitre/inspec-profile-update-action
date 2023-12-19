control 'SV-251001' do
  title 'MobileIron Sentry must be configured to implement cryptographic mechanisms using a FIPS 140-2 approved algorithm to protect the confidentiality of remote maintenance sessions.'
  desc 'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to eavesdropping, potentially putting sensitive data (including administrator passwords) at risk of compromise and potentially allowing hijacking of maintenance sessions.'
  desc 'check', 'On MobileIron Sentry console, do the following to verify FIPS mode is activated to protect the confidentiality of remote maintenance sessions: 
 
1. SSH to the MobileIron Sentry. 
2. Run the "show FIPS" command.
3. Verify FIPS 140 mode is not disabled. 

If FIPS 140-2 mode is disabled, this is a finding.'
  desc 'fix', 'Configure MobileIron Sentry to use FIPS 140-2 approved algorithms to protect the confidentiality of remote maintenance sessions:

1. SSH to the MobileIron Sentry.
2. At the prompt, enter "enable" mode with the secret credentials.
3. Type Configure command.
4. Type FIPS.
5. Once reloaded, SSH to the MobileIron Sentry.
6. Run the "show FIPS" command. 

FIPS 140 mode is enabled.'
  impact 0.7
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x NDM'
  tag check_id: 'C-54436r802223_chk'
  tag severity: 'high'
  tag gid: 'V-251001'
  tag rid: 'SV-251001r802225_rule'
  tag stig_id: 'MOIS-ND-000810'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-54390r802224_fix'
  tag 'documentable'
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
