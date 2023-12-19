control 'SV-258325' do
  title 'Apple iOS/iPadOS 17 must be configured to enforce a passcode reuse prohibition of at least two generations.'
  desc 'iOS-iPadOS 17 includes a new feature that allows the previous passcode to be valid for 72 hours after a passcode change. If the previous passcode has been compromised and the attacker has access to it and the Apple device, enterprise data and the enterprise network can be compromised. Currently there is no MDM control to force the old passcode to expire immediately after passcode change. The previous passcode will expire immediately after a passcode change if the MDM password history control is implemented.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review configuration settings to confirm the Apple iOS or iPadOS device has a passcode reuse prohibition of at least two generations.

This procedure is performed in the Apple iOS/iPadOS management tool and on the iPhone and iPad. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Management tool, verify the "Passcode History" value is set to two or greater.

On the iPhone and iPad:
1. Open the Settings app. 
2. Tap "General".
3. Tap "VPN & Device Management".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the password policy.
5. Tap "Restrictions".
6. Tap "Passcode".
7. Verify "Number of unique recent passcodes required" is listed as "two" or greater.

If the Apple iOS or iPadOS device does not enforce a passcode reuse prohibition of at least two generations, this is a finding.'
  desc 'fix', 'Install a configuration profile to enforce a passcode reuse prohibition of at least two generations (passcode history).'
  impact 0.7
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62066r927656_chk'
  tag severity: 'high'
  tag gid: 'V-258325'
  tag rid: 'SV-258325r927658_rule'
  tag stig_id: 'AIOS-17-006950'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-61990r927657_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
