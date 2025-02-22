control 'SV-230101' do
  title 'The Motorola Android Pie Work Profile must be configured to prevent users from adding personal email accounts to the work email app.'
  desc 'If the user is able to add a personal email account (POP3, IMAP, EAS) to the work email app, it could be used to forward sensitive DoD data to unauthorized recipients. Restricting email account addition to the Administrator or restricting email account addition to whitelisted accounts mitigates this vulnerability.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review the Motorola Android Pie Work Profile configuration settings to confirm that users are prevented from adding personal email accounts to the work email app. 
 
This procedure is performed on both the MDM Administrator console and the Motorola Android Pie device. 
 
On the MDM console: 
1. Open the User restrictions setting.
2. Verify that "Disallow add accounts" is set to "On".

On the Android Pie device: 
1. Open Settings. 
2. Tap "Accounts". 
3. Verify that "Add account" is grayed out under the Work section.
 
If on the MDM console the restriction to "Disallow add accounts" is not set, or On the Android Pie device the user is able to add an account, this is a finding.'
  desc 'fix', %q(Configure the Motorola Android Pie Work Profile to prevent users from adding personal email accounts to the work email app. 
 
On the MDM console, for the Work Profile: 
1. Open the User restrictions setting.
2. Set "Disallow modify accounts" to "On".

Refer to the MDM documentation to determine how to provision users' work email accounts for the work email app.)
  impact 0.5
  ref 'DPMS Target Motorola Android 9.x COPE STIG'
  tag check_id: 'C-32416r538299_chk'
  tag severity: 'medium'
  tag gid: 'V-230101'
  tag rid: 'SV-230101r569708_rule'
  tag stig_id: 'MOTO-09-009200'
  tag gtitle: 'GOOG-09-009200'
  tag fix_id: 'F-32394r538300_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
