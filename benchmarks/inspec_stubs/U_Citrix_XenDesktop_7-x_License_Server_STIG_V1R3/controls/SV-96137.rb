control 'SV-96137' do
  title 'XenDesktop License Server must implement cryptographic mechanisms to prevent unauthorized disclosure of information and/or detect changes to information during transmission unless otherwise protected by alternative physical safeguards, such as, at a minimum, a Protected Distribution Systems (PDS).'
  desc 'Encrypting information for transmission protects information from unauthorized disclosure and modification. Cryptographic mechanisms implemented to protect information integrity include, for example, cryptographic hash functions that have common application in digital signatures, checksums, and message authentication codes. 

This requirement applies only to applications that are distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications need to leverage transmission protection mechanisms, such as TLS, SSL VPNs, or IPsec.

Alternative physical protection measures include PDS. PDSs are used to transmit unencrypted classified National Security Information (NSI) through an area of lesser classification or control. Since the classified NSI is unencrypted, the PDS must provide adequate electrical, electromagnetic, and physical safeguards to deter exploitation.'
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
  impact 0.7
  ref 'DPMS Target XenDesktop 7.x License Service'
  tag check_id: 'C-81163r1_chk'
  tag severity: 'high'
  tag gid: 'V-81423'
  tag rid: 'SV-96137r1_rule'
  tag stig_id: 'CXEN-LS-001005'
  tag gtitle: 'SRG-APP-000440'
  tag fix_id: 'F-88239r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002421']
  tag nist: ['SC-8 (1)']
end
