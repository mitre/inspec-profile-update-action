control 'SV-102945' do
  title 'Samsung Android must be configured to prevent users from adding personal email accounts to the work email app.'
  desc 'If the user is able to add a personal email account (POP3, IMAP, EAS) to the work email app, it could be used to forward sensitive DoD data to unauthorized recipients. Restricting email account addition to the administrator or restricting email account addition to whitelisted accounts mitigates this vulnerability.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', %q(Review device configuration settings to confirm that users are prevented from adding personal email accounts to the work email app. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, do the following: 
1. In the "Android account" group, verify that "account management" is configured to "disable for the work email app". 
2. Provision the user's email account for the work email app. 

On the Samsung Android device, do the following: 
1. Open Settings. 
2. Tap "Accounts and backup". 
3. Tap "Accounts". 
4. Tap "Add account". 
5. Verify that an account for the work email app cannot be added. 

If on the MDM console "account management" is not disabled for the work email app, or on the Samsung Android device the user can add an account for the work email app, this is a finding.)
  desc 'fix', %q(Configure Samsung Android to prevent users from adding personal email accounts to the work email app. 

On the MDM console, for the device, do the following: 
1. In the "Android account" group, configure "account management" to "disable for the work email app". 
2. Provision the user's email account for the work email app. 

Refer to the MDM documentation to determine how to provision users' work email accounts for the work email app.)
  impact 0.5
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COBO KPE(AE)'
  tag check_id: 'C-92163r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92857'
  tag rid: 'SV-102945r1_rule'
  tag stig_id: 'KNOX-09-000010'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-99101r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
