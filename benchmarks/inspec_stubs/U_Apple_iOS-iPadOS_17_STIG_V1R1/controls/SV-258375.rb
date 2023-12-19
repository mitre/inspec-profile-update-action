control 'SV-258375' do
  title 'Apple iOS/iPadOS 17 must have DOD root and intermediate PKI certificates installed.'
  desc 'DOD root and intermediate PKI certificates are used to verify the authenticity of PKI certificates of users and web services. If the user is allowed to remove root and intermediate certificates, the user could allow an adversary to falsely sign a certificate in such a way that it could not be detected. Restricting the ability to remove DOD root and intermediate PKI certificates to the Administrator mitigates this risk.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', 'Verify DOD intermediate and root certificates have been installed on Apple devices.

In the iOS management tool, verify the DOD intermediate and root certificates are installed on the Apple device.

On the iPhone and iPad device:
1. Open the Settings app.
2. Tap "General".
3. Tap "VPN & Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Tap "More Details".
7. Verify the DOD intermediate and root certificates are listed.

If DOD intermediate and root certificates are not installed on the Apple device, this is a finding.'
  desc 'fix', 'Install DOD intermediate and root certificates on managed mobile devices using the MDM.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62116r927806_chk'
  tag severity: 'medium'
  tag gid: 'V-258375'
  tag rid: 'SV-258375r927808_rule'
  tag stig_id: 'AIOS-17-014700'
  tag gtitle: 'PP-MDF-333350'
  tag fix_id: 'F-62040r927807_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
