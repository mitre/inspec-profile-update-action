control 'SV-228597' do
  title 'Google Android 11 must allow only the administrator (EMM) to install/remove DoD root and intermediate PKI certificates.'
  desc 'DoD root and intermediate PKI certificates are used to verify the authenticity of PKI certificates of users and web services. If the user is allowed to remove root and intermediate certificates, the user could allow an adversary to falsely sign a certificate in such a way that it could not be detected. Restricting the ability to remove DoD root and intermediate PKI certificates to the Administrator mitigates this risk.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', 'Review the device configuration to confirm that the user is unable to remove DoD root and intermediate PKI certificates.

On the EMM console:
1. Open "Set user restrictions".
2. Verify that "Disallow config credentials" is toggled to On.

On the Google Android 11 device, do the following: 
1. Open Settings. 
2. Tap "Security". 
3. Tap "Advanced".
4. Tap "Encryption & credentials".
5. Tap "Trusted credentials".
6. Verify that the user is unable to untrust or remove any work certificates.
 
If on the Google Android 11 device the user is able to remove certificates, this is a finding.'
  desc 'fix', 'Configure Google Android 11 device to prevent a user from removing DoD root and intermediate PKI certificates.

On the EMM console:
1. Open "Set user restrictions".
2. Toggle "Disallow config credentials" to On.'
  impact 0.5
  ref 'DPMS Target Google Android 11 COBO'
  tag check_id: 'C-30832r505616_chk'
  tag severity: 'medium'
  tag gid: 'V-228597'
  tag rid: 'SV-228597r619923_rule'
  tag stig_id: 'GOOG-11-009100'
  tag gtitle: 'PP-MDF-992000'
  tag fix_id: 'F-30809r505617_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
