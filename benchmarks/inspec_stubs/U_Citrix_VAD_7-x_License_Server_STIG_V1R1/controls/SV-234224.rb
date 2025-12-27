control 'SV-234224' do
  title 'Citrix License Server must protect the authenticity of communications sessions.'
  desc 'Authenticity protection provides protection against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

Application communication sessions are protected using transport encryption protocols, such as SSL or TLS. SSL/TLS provide web applications with a way to authenticate user sessions and encrypt application traffic. Session authentication can be single (one-way) or mutual (two-way) in nature. Single authentication authenticates the server for the client, whereas mutual authentication provides a means for both the client and the server to authenticate each other. 

This requirement applies to applications that use communications sessions. This includes but is not limited to web-based applications and Service-Oriented Architectures (SOA). 

This requirement addresses communications protection at the application session, versus the network packet, and establishes grounds for confidence at both ends of communications sessions in ongoing identities of other parties and in the validity of information transmitted. Depending on the required degree of confidentiality and integrity, web services/SOA will require the use of SSL/TLS mutual authentication (two-way/bidirectional).'
  desc 'check', 'Look in \\\\Citrix\\Licensing\\LS\\conf\\ folder of the License Server installation directory for cert file/cert key file.

Open the License Management Console, click "Administration", and select the "Server Configuration" tab.

Click the "Secure Web Server Configuration" bar and verify "Select Enable HTTPS (Default 443)" is selected.

If "Select Enable HTTPS (Default 443)" is not selected, this is a finding.

NOTE: The user may be prompted to log in after "Administration".'
  desc 'fix', '1. Copy a valid server certificate file and server certificate key file into the \\\\Citrix\\Licensing\\LS\\conf\\ folder of the License Server installation directory.

2. Click "Administration" and select the "Server Configuration" tab.

3. Click the "Secure Web Server Configuration" bar.

4. Select "Enable HTTPS (Default 443)".

5. Enter a port for the HTTPS communication.

6. Enter the location of the server certificate file and the server certificate key file.

7. Stop and restart the Citrix Licensing service from the services control panel of the machine running the license server.'
  impact 0.5
  ref 'DPMS Target Citrix VAD 7.x License Server'
  tag check_id: 'C-37409r611923_chk'
  tag severity: 'medium'
  tag gid: 'V-234224'
  tag rid: 'SV-234224r628795_rule'
  tag stig_id: 'CVAD-LS-000480'
  tag gtitle: 'SRG-APP-000219'
  tag fix_id: 'F-37374r611924_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
