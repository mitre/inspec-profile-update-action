control 'SV-231051' do
  title 'Samsung Android Work Environment must allow only the Administrator (management tool) to perform the following management function: install/remove DoD root and intermediate PKI certificates.'
  desc 'DoD root and intermediate PKI certificates are used to verify the authenticity of PKI certificates of users and web services. If the user is allowed to remove root and intermediate certificates, the user could allow an adversary to falsely sign a certificate in such a way that it could not be detected. Restricting the ability to remove DoD root and intermediate PKI certificates to the Administrator mitigates this risk.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', 'Review Samsung Android Work Environment configuration settings to determine if the user is unable to remove DoD root and intermediate PKI certificates.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool, in the Work Environment restrictions section, verify "User Remove Certificates" is set to "Disallow".

On the Samsung Android device: 
1. Open Settings >> Biometrics and security >> Other security settings >> View security certificates.
2. In the System tab, verify that no listed certificate in the Work Environment can be untrusted.
3. In the User tab, verify that no listed certificate in the Work Environment can be removed.

If on the management tool the device "User Remove Certificates" is not set to "Disallow", or on the Samsung Android device a certificate can be untrusted or removed, this is a finding.'
  desc 'fix', 'Configure Samsung Android Work Environment to prevent a user from removing DoD root and intermediate PKI certificates.

On the management tool, in the Work Environment restrictions section, set "User Remove Certificates" to "Disallow".'
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x Legacy'
  tag check_id: 'C-33981r592767_chk'
  tag severity: 'medium'
  tag gid: 'V-231051'
  tag rid: 'SV-231051r608683_rule'
  tag stig_id: 'KNOX-11-023200'
  tag gtitle: 'PP-MDF-992000'
  tag fix_id: 'F-33954r592768_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
