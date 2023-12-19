control 'SV-228759' do
  title 'Apple iOS/iPadOS must implement the management setting: use SSL for Exchange ActiveSync.'
  desc 'Exchange email messages are a form of data in transit and thus are vulnerable to eavesdropping and man-in-the-middle attacks. Secure Sockets Layer (SSL), also referred to as Transport Layer Security (TLS), provides encryption and authentication services that mitigate the risk of breach.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review configuration settings to confirm "Use SSL" for the Exchange account is enabled.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Use SSL" is checked under the Exchange payload.

Alternatively, verify the text "<key>SSL</key><true/>" appears in the configuration profile (.mobileconfig file).

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management" or "Profiles".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the Exchange policy.
5. Tap "Accounts".
6. Tap the name of the Exchange account. 
7. Verify "SSL" is set to "Yes".

If "Use SSL" is unchecked in the Apple iOS/iPadOS management tool, "<key>SSL</key><false/>" appears in the configuration profile, or the Exchange policy on the iPhone and iPad has "SSL" set to "No", this is a finding.'
  desc 'fix', 'Install a configuration profile to use SSL for Exchange ActiveSync.'
  impact 0.5
  ref 'DPMS Target Apple iOS iPadOS 14'
  tag check_id: 'C-30994r509905_chk'
  tag severity: 'medium'
  tag gid: 'V-228759'
  tag rid: 'SV-228759r561031_rule'
  tag stig_id: 'AIOS-14-009700'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-30971r509906_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
