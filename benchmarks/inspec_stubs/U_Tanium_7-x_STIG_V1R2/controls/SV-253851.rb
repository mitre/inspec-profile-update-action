control 'SV-253851' do
  title 'The Tanium Server certificates must have Extended Key Usage entries for the serverAuth object TLS Web Server Authentication and the clientAuth object TLS Web Client Authentication.'
  desc "Restricting this setting limits the user's ability to change their password. Passwords must be changed at specific policy-based intervals; however, if the application allows the user to immediately and continually change their password, it could be changed repeatedly in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', '1. Access the Tanium application server interactively.

2. Log on to the server with an account that has administrative privileges.

3. Navigate to Program Files >> Tanium >> Tanium Server.

4. Locate the "SOAPServer.crt" file.

5. Double-click the file to open the certificate.

6. Select the "Details" tab.

7. Scroll down through the details to find and select the "Enhanced Key Usage" field.

If there is no "Enhanced Key Usage" field, this is a finding.

In the bottom screen, verify "Server Authentication" and "Client Authentication" are both identified.

If "Server Authentication" and "Client Authentication" are not both identified, this is a finding.'
  desc 'fix', 'Request or regenerate the certificate being used to include both the "Server Authentication" and "Client Authentication" objects.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57303r842579_chk'
  tag severity: 'medium'
  tag gid: 'V-253851'
  tag rid: 'SV-253851r842581_rule'
  tag stig_id: 'TANS-SV-000020'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-57254r842580_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
