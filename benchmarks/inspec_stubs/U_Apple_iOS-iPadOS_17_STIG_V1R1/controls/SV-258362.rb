control 'SV-258362' do
  title 'Apple iOS/iPadOS 17 must disable "Password AutoFill" in browsers and applications.'
  desc "The AutoFill functionality in browsers and applications allows the user to complete a form that contains sensitive information, such as PII, without previous knowledge of the information. By allowing the use of the AutoFill functionality, an adversary who learns a user's iPhone and iPad passcode, or who otherwise is able to unlock the device, may be able to further breach other systems by relying on the AutoFill feature to provide information unknown to the adversary. By disabling the AutoFill functionality, the risk of an adversary gaining further information about the device's user or compromising other systems is significantly mitigated.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'This a supervised-only control. If the iPhone or iPad being reviewed is not supervised by the MDM, this control is automatically a finding.

If the iPhone or iPad being reviewed is supervised by the MDM, review configuration settings to confirm "Password AutoFill is not allowed" is disabled.

This check procedure is performed on both the iOS/iPadOS device management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS/iPadOS management tool, verify "Password AutoFill is not allowed" is unchecked.

On the iPhone/iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "VPN & Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Password AutoFill is not allowed" is listed.

If "Password AutoFill is not allowed" is not enabled in the iOS/iPadOS management tool and on the Apple device, this is a finding.'
  desc 'fix', 'Install a configuration profile to disable allow Password AutoFill in the management tool. This a supervised-only control.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62103r927767_chk'
  tag severity: 'medium'
  tag gid: 'V-258362'
  tag rid: 'SV-258362r927769_rule'
  tag stig_id: 'AIOS-17-012700'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62027r927768_fix'
  tag 'documentable'
  tag cci: ['CCI-000097', 'CCI-000366']
  tag nist: ['AC-20 (2)', 'CM-6 b']
end
