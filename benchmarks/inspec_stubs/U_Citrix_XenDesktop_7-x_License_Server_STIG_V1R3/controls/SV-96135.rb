control 'SV-96135' do
  title 'XenDesktop License Server must protect the confidentiality and integrity of transmitted information.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and read or altered. 

This requirement applies only to applications that are distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications need to leverage transmission protection mechanisms, such as TLS, SSL VPNs, or IPsec.

Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, logical means (cryptography) do not have to be employed, and vice versa.'
  desc 'check', 'Open the License Management Console, click "Administration", and select the "Server Configuration" tab.

Click the "Secure Web Server Configuration" bar and verify "Select Enable HTTPS (Default 443)" is selected.

If "Select Enable HTTPS (Default 443)" is not selected, this is a finding.'
  desc 'fix', '1. Copy a valid server certificate file and server certificate key file into the \\\\Citrix\\Licensing\\LS\\conf\\ folder of the License Server installation directory.
2. Click "Administration" and select the "Server Configuration" tab.
3. Click the "Secure Web Server Configuration" bar.
4. Select "Enable HTTPS (Default 443)".
5. Enter a port for the HTTPS communication.
6. Enter the location of the server certificate file and the server certificate key file.
7. Stop and restart the Citrix Licensing service from the services control panel of the machine running the license server.'
  impact 0.5
  ref 'DPMS Target XenDesktop 7.x License Service'
  tag check_id: 'C-81161r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81421'
  tag rid: 'SV-96135r1_rule'
  tag stig_id: 'CXEN-LS-001000'
  tag gtitle: 'SRG-APP-000439'
  tag fix_id: 'F-88237r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
