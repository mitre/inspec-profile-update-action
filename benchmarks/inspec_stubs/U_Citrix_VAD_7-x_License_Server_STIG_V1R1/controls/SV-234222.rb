control 'SV-234222' do
  title 'Citrix License Server must implement DoD-approved encryption to protect the confidentiality of remote access sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session. 

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. 
 
Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection, thereby providing a degree of confidentiality. The encryption strength of the mechanism is selected based on the security categorization of the information.'
  desc 'check', 'Open the License Management Console, click "Administration", and select the "Server Configuration" tab.

Click the "Secure Web Server Configuration" bar and verify "Select Enable HTTPS (Default 443)" is selected.

If "Select Enable HTTPS (Default 443)" is not selected, this is a finding.'
  desc 'fix', '1. Copy a valid server certificate file and server certificate key file to the \\\\Citrix\\Licensing\\LS\\conf\\ folder of the License Server installation directory.

2. Click “Administration” and select the "Server Configuration" tab.

3. Click the "Secure Web Server Configuration" bar.

4. Select "Enable HTTPS (Default 443)".

5. Enter a port for the HTTPS communication.

6. Enter the location of the server certificate file and the server certificate key file.

7. Stop and restart the Citrix Licensing service from the services control panel of the machine running the license server.

NOTE: The user may be prompted to log in after "Administration".
Port must be 8082 (or desired port from PPSM group).'
  impact 0.7
  ref 'DPMS Target Citrix VAD 7.x License Server'
  tag check_id: 'C-37407r611917_chk'
  tag severity: 'high'
  tag gid: 'V-234222'
  tag rid: 'SV-234222r628795_rule'
  tag stig_id: 'CVAD-LS-000030'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-37372r611918_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
