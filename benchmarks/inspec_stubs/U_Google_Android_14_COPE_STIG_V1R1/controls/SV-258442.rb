control 'SV-258442' do
  title 'The Google Android 14 must allow only the administrator (EMM) to install/remove DOD root and intermediate PKI certificates.'
  desc 'DOD root and intermediate PKI certificates are used to verify the authenticity of PKI certificates of users and web services. If the user is allowed to remove root and intermediate certificates, the user could allow an adversary to falsely sign a certificate in such a way that it could not be detected. Restricting the ability to remove DOD root and intermediate PKI certificates to the Administrator mitigates this risk.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', 'Review the device configuration to confirm that the user is unable to remove DOD root and intermediate PKI certificates.

On the EMM console:
1. Open "Set user restrictions".
2. Verify "Disallow config credentials" is toggled to "ON".

On the Google Android 14 device:
1. Open Settings.
2. Tap "Security & privacy".
3. Tap "More security & privacy".
4. Tap "Encryption & credentials".
5. Tap "Trusted credentials".
6. Verify the user is unable to untrust or remove any work certificates.
 
If on the Google Android 14 device the user is able to remove certificates, this is a finding.'
  desc 'fix', 'Configure Google Android 14 device to prevent a user from removing DOD root and intermediate PKI certificates.

On the EMM console:
1. Open "Set user restrictions".
2. Toggle "Disallow config credentials" to "ON".'
  impact 0.5
  ref 'DPMS Target Google Android 14 COPE'
  tag check_id: 'C-62183r928349_chk'
  tag severity: 'medium'
  tag gid: 'V-258442'
  tag rid: 'SV-258442r928351_rule'
  tag stig_id: 'GOOG-14-012300'
  tag gtitle: 'PP-MDF-333350'
  tag fix_id: 'F-62107r928350_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
