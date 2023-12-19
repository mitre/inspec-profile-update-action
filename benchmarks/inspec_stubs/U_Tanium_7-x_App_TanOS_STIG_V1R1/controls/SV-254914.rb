control 'SV-254914' do
  title 'The Tanium Server certificates must have Extended Key Usage entries for the serverAuth object TLS Web Server Authentication and the clientAuth object TLS Web Client Authentication.'
  desc "Restricting this setting limits the user's ability to change their password. Passwords need to be changed at specific policy based intervals; however, if the application allows the user to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', 'From Browser:

1. Navigate to the Tanium Console URI and log in using multi-factor authentication.

2. Click the lock to the left of the URI in the address bar.

3. Select the lock on the left of the URI in the address bar:
    a) Chrome: Select "Certificate".
    b) Edge: Select "Connection is Secure," and then select the certificate icon on the right.

4. Select the "Details" tab.

5. Scroll down through the details to find and select the "Enhanced Key Usage" field.

If there is no "Enhanced Key Usage" field, this is a finding.

In the bottom screen, verify "Server Authentication" and "Client Authentication" are both identified.

If "Server Authentication" and "Client Authentication" are not both identified, this is a finding.

From Server:

1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "2" for "Tanium Operations Menu," and then press "Enter".

4. Press "7" for "Download SOAP Certificate," and then press "Enter".

5. In a browser with access to the Tanium Server Console, navigate to https://<tanium server>/pub/SOAPServer.crt.

6. Download the SOAPServer.crt file when prompted.

7. Double-click on the file to open the certificate.

8. Select the "Details" tab.

9. Scroll down through the details to find and select the "Enhanced Key Usage" field.

If there is no "Enhanced Key Usage" field, this is a finding.

In the bottom screen, verify "Server Authentication" and "Client Authentication" are both identified.

If "Server Authentication" and "Client Authentication" are not both identified, this is a finding.'
  desc 'fix', 'Request or regenerate the certificate being used to include both the "Server Authentication" and "Client Authentication" objects.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58527r867640_chk'
  tag severity: 'medium'
  tag gid: 'V-254914'
  tag rid: 'SV-254914r867642_rule'
  tag stig_id: 'TANS-AP-000480'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-58471r867641_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
