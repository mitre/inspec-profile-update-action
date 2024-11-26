control 'SV-258348' do
  title 'Apple iOS/iPadOS 17 must implement the management setting: use SSL for Exchange ActiveSync.'
  desc 'Exchange email messages are a form of data in transit and thus are vulnerable to eavesdropping and man-in-the-middle attacks. Secure Sockets Layer (SSL), also referred to as Transport Layer Security (TLS), provides encryption and authentication services that mitigate the risk of breach.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review configuration settings to confirm "Use SSL" for the Exchange account is enabled for incoming mail.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Use SSL for incoming mail" is checked under the Exchange payload.

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "VPN & Device Management".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the Exchange policy.
5. Tap "Mail".
6. Tap the name of the Exchange account. 
7. Verify "SSL for incoming mail" is set to "Yes".

If "Use SSL for incoming mail" is unchecked in the Apple iOS/iPadOS management tool or the Exchange policy on the iPhone and iPad has "SSL for incoming mail" set to "No", this is a finding.'
  desc 'fix', 'Install a configuration profile to use SSL for Exchange ActiveSync incoming mail.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62089r927725_chk'
  tag severity: 'medium'
  tag gid: 'V-258348'
  tag rid: 'SV-258348r927727_rule'
  tag stig_id: 'AIOS-17-011300'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62013r927726_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
