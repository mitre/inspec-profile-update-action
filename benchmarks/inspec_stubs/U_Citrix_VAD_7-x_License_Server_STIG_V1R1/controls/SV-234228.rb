control 'SV-234228' do
  title 'Citrix License Server must maintain the confidentiality and integrity of information during reception.'
  desc 'Information can be unintentionally or maliciously disclosed or modified during reception including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

This requirement applies only to applications that are distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When receiving data, applications need to leverage protection mechanisms, such as TLS, SSL VPNs, or IPsec.'
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
  ref 'DPMS Target Citrix VAD 7.x License Server'
  tag check_id: 'C-37413r611935_chk'
  tag severity: 'medium'
  tag gid: 'V-234228'
  tag rid: 'SV-234228r628795_rule'
  tag stig_id: 'CVAD-LS-001015'
  tag gtitle: 'SRG-APP-000442'
  tag fix_id: 'F-37378r611936_fix'
  tag 'documentable'
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end
