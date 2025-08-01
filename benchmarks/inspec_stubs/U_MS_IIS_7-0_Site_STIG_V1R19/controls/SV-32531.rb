control 'SV-32531' do
  title 'A private web server must have a valid server certificate.'
  desc 'This check verifies the server certificate is actually a DoD-issued certificate used by the organization being reviewed. This is used to verify the authenticity of the web site to the user. If the certificate is not issued by the DoD or if the certificate has expired, then there is no assurance the use of the certificate is valid. The entire purpose of using a certificate is, therefore, compromised.'
  desc 'check', '1. Open the IIS Manager.
2. Click on the Server name.
3. Double-Click the Server Certificate icon.
4. Double-Click each certificate and verify the certificate path is to a DoD root CA.  If not, this is a finding.'
  desc 'fix', '1. Open the IIS Manager. 
2. Click on the Server name. 
3. Double-Click the Server Certificate icon.
4. Import a valid DoD certificate and remove any non-DoD certificates.'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-33498r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2263'
  tag rid: 'SV-32531r2_rule'
  tag stig_id: 'WG350 IIS7'
  tag gtitle: 'WG350'
  tag fix_id: 'F-29200r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
