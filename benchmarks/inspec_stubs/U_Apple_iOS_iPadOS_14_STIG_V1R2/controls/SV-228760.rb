control 'SV-228760' do
  title 'Apple iOS/iPadOS must implement the management setting: not allow messages in an ActiveSync Exchange account to be forwarded or moved to other accounts in the Apple iOS/iPadOS Mail app.'
  desc 'The Apple iOS/iPadOS Mail app can be configured to support multiple email accounts concurrently. These email accounts are likely to involve content of varying degrees of sensitivity (e.g., both personal and enterprise messages). To prevent the unauthorized and undetected forwarding or moving of messages from one account to another, Mail ActiveSync Exchange accounts can be configured to block such behavior. While users may still send a message from the Exchange account to another account, these transactions must involve an Exchange server, enabling audit records of the transaction, filtering of mail content, and subsequent forensic analysis.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review configuration settings to confirm "Allow messages to be moved" is disabled.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Allow messages to be moved" is unchecked under the Exchange payload.

Alternatively, verify the text "<key>PreventMove</key><true/>" appears in the configuration profile (.mobileconfig file).

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management" or "Profiles".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the Exchange policy.
5. Tap "Accounts".
6. Tap the "name of the Exchange account".
7. Verify "Prevent Move" is set to "Yes".

If "Allow messages to be moved" is checked in the Apple iOS/iPadOS management tool, "<key>PreventMove</key><false/>" appears in the configuration profile, or the Exchange policy on the iPhone and iPad has "Prevent Move" set to "No", this is a finding.'
  desc 'fix', 'Install a configuration profile to prevent Exchange messages from being moved or forwarded between email accounts.'
  impact 0.5
  ref 'DPMS Target Apple iOS iPadOS 14'
  tag check_id: 'C-30995r509908_chk'
  tag severity: 'medium'
  tag gid: 'V-228760'
  tag rid: 'SV-228760r561031_rule'
  tag stig_id: 'AIOS-14-009800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-30972r509909_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000764', 'CCI-000370']
  tag nist: ['CM-6 b', 'IA-2', 'CM-6 (1)']
end
