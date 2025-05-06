control 'SV-242556' do
  title 'Zebra Android 10 must allow only the administrator (MDM) to install/remove DoD root and intermediate PKI certificates.'
  desc 'DoD root and intermediate PKI certificates are used to verify the authenticity of PKI certificates of users and web services. If the user is allowed to remove root and intermediate certificates, the user could allow an adversary to falsely sign a certificate in such a way that it could not be detected. Restricting the ability to remove DoD root and intermediate PKI certificates to the Administrator mitigates this risk.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', 'Review the device configuration to confirm that the user is unable to remove DoD root and intermediate PKI certificates.

On the MDM console:
1. Open the User restrictions setting.
2. Verify that "Disallow config credentials" is set to On for the work profile.

On the Zebra Android 10 device: 
1. Open Settings. 
2. Tap "Security". 
3. Tap "Advanced".
4. Tap "Encryption & credentials".
5. Tap "Trusted credentials".
6. Verify that the user is unable to untrust or remove any work certificates.
 
If on the Zebra Android 10 device the user is able to remove certificates, this is a finding.'
  desc 'fix', 'Configure Zebra Android 10 to prevent a user from removing DoD root and intermediate PKI certificates.

On the MDM console:
1. Open User restrictions.
2. Set "Disallow config credentials" to On for the work profile.'
  impact 0.5
  ref 'DPMS Target Zebra Android 10 COPE'
  tag check_id: 'C-45831r714511_chk'
  tag severity: 'medium'
  tag gid: 'V-242556'
  tag rid: 'SV-242556r714513_rule'
  tag stig_id: 'ZEBR-10-009100'
  tag gtitle: 'PP-MDF-992000'
  tag fix_id: 'F-45788r714512_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
