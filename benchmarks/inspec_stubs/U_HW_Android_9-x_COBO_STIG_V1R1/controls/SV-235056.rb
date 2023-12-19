control 'SV-235056' do
  title 'The Honeywell Mobility Edge Android Pie must allow only the administrator (MDM) to install/remove DoD root and intermediate PKI certificates.'
  desc 'DoD root and intermediate PKI certificates are used to verify the authenticity of PKI certificates of users and web services. If the user is allowed to remove root and intermediate certificates, the user could allow an adversary to falsely sign a certificate in such a way that it could not be detected. Restricting the ability to remove DoD root and intermediate PKI certificates to the Administrator mitigates this risk.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', 'Review the device configuration to confirm that the user is unable to remove DoD root and intermediate PKI certificates.

On the MDM console:
1. Open the User restrictions setting.
2. Verify that "Disallow config credentials" is set to "on" for the work profile.

On the Honeywell Android Pie device: 
1. Open Settings. 
2. Tap "Security & Location". 
3. Tap on "Advanced".
4. Tap on "Encryption & credentials".
5. Tap on "Trusted credentials".
6. Verify that the user is unable to untrust or remove any work certificates.
 
If on the Honeywell Android Pie device the user is able to remove certificates, this is a finding.'
  desc 'fix', 'Configure Honeywell Mobility Edge Android Pie devices to prevent a user from removing DoD root and intermediate PKI certificates.

On the MDM console:
1. Open the User restrictions setting.
2. Set "Disallow config credentials" to "on" for the work profile.'
  impact 0.5
  ref 'DPMS Target Honeywell Android 9.x COBO'
  tag check_id: 'C-38244r623078_chk'
  tag severity: 'medium'
  tag gid: 'V-235056'
  tag rid: 'SV-235056r626530_rule'
  tag stig_id: 'HONW-09-009100'
  tag gtitle: 'PP-MDF-992000'
  tag fix_id: 'F-38207r623079_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
