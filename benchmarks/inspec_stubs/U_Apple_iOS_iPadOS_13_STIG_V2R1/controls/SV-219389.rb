control 'SV-219389' do
  title 'Apple iOS/iPadOS must disable password autofill in browsers and applications.'
  desc "The AutoFill functionality in browsers and applications allows the user to complete a form that contains sensitive information, such as PII, without previous knowledge of the information. By allowing the use of the AutoFill functionality, an adversary who learns a user's iPhone and iPad passcode, or who otherwise is able to unlock the device, may be able to further breach other systems by relying on the AutoFill feature to provide information unknown to the adversary. By disabling the AutoFill functionality, the risk of an adversary gaining further information about the device's user or compromising other systems is significantly mitigated.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'This a Supervised-only control. If the iPhone or iPad being reviewed is not Supervised by the MDM, this control is automatically a finding.

If the iPhone or iPad being reviewed is Supervised by the MDM, review configuration settings to confirm "Allow Password Autofill" is disabled.

This check procedure is performed on both the iOS/iPadOS device management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS/iPadOS management tool, verify "Allow Password Autofill" is unchecked.

On the iPhone/iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles" or "Profiles & Device Management" or "Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Password Autofill is not allowed" is not listed.

If "Password Autofill is not allowed" is not disabled in both the iOS/iPadOS management tool and on the Apple device, this is a finding.'
  desc 'fix', 'Install a configuration profile to disable the allow password autofill in the management tool. This a Supervised-only control.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 13'
  tag check_id: 'C-21114r547678_chk'
  tag severity: 'medium'
  tag gid: 'V-219389'
  tag rid: 'SV-219389r604137_rule'
  tag stig_id: 'AIOS-13-013200'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-21113r547679_fix'
  tag 'documentable'
  tag legacy: ['SV-106611', 'V-97507']
  tag cci: ['CCI-000097', 'CCI-000370', 'CCI-000366']
  tag nist: ['AC-20 (2)', 'CM-6 (1)', 'CM-6 b']
end
