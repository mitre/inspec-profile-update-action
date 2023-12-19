control 'SV-251827' do
  title 'Samsung Android must allow only the Administrator (management tool) to perform the following management function: install/remove DoD root and intermediate PKI certificates.'
  desc 'DoD root and intermediate PKI certificates are used to verify the authenticity of PKI certificates of users and web services. If the user is allowed to remove root and intermediate certificates, the user could allow an adversary to falsely sign a certificate in such a way that it could not be detected. Restricting the ability to remove DoD root and intermediate PKI certificates to the Administrator mitigates this risk.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are preventing users from removing DoD root and intermediate PKI certificates.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the device restrictions, verify that "Config credentials" is set to "Disallow".

On the Samsung Android device: 
1. Open Settings >> Biometrics and security >> Other security settings >> View security certificates.
2. In the System tab, verify that no listed certificate in the Device can be untrusted.
3. In the User tab, verify that no listed certificate in the Device can be removed.

If on the management tool the device "Config credentials" is not set to "Disallow", or on the Samsung Android device a certificate can be untrusted or removed, this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to prevent users from removing DoD root and intermediate PKI certificates.

On the management tool, in the device restrictions, set "Config credentials" to "Disallow".'
  impact 0.5
  ref 'DPMS Target Samsung Android 12 KPE 3.x COBO'
  tag check_id: 'C-55287r814235_chk'
  tag severity: 'medium'
  tag gid: 'V-251827'
  tag rid: 'SV-251827r814237_rule'
  tag stig_id: 'KNOX-12-110250'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-55241r814236_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
