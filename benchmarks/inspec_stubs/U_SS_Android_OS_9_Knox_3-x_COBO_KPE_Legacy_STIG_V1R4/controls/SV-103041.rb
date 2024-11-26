control 'SV-103041' do
  title 'Samsung Android must be configured to prevent users from adding personal email accounts to the work email app.'
  desc 'If the user is able to add a personal email account (POP3, IMAP, EAS) to the work email app, it could be used to forward sensitive DoD data to unauthorized recipients. Restricting email account addition to the administrator or restricting email account addition to whitelisted accounts mitigates this vulnerability.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', %q(Review device configuration settings to confirm that users are prevented from adding personal email accounts to the work email app. 

This procedure is performed on both the MDM Administrator console and the Samsung Android device. 

Confirm if Method #1 or Method #2 is used at the Samsung device site and follow the appropriate procedure. 

**** 

Method #1: On the MDM console, for the device, in the "Knox account" group, verify that the account addition whitelist only includes DoD-approved email domains. 

Refer to the MDM documentation to determine if the account addition blacklist is also required to be configured when enforcing an account addition whitelist. 

On the Samsung Android device, do the following: 
1. Open Settings. 
2. Tap "Accounts and backup". 
3. Tap "Add account". 
4. Tap the account type for the work email app. 
5. Verify that an account with a DoD-approved email domain can be added. 
6. Verify that an account without a DoD-approved email domain cannot be added. 

If on the MDM console the account addition whitelist includes domains that are not DoD-approved email domains, or on the Samsung Android device the user is able to add an account without a DoD-approved email domain, this is a finding. 

**** 

Method #2: On the MDM console, for the device, do the following: 
1. In the "Knox account" group, verify that all email domains are blacklisted in the account addition blacklist. 
2. Verify that the user's email account for the work email app has been provisioned. 

Refer to the MDM documentation to determine how to verify that a user's work email account is provisioned for the work email app. 

On the Samsung Android device, do the following: 
1. Open Settings. 
2. Tap "Accounts and backup". 
3. Tap "Accounts". 
4. Tap "Add account". 
5. Verify that no accounts can be added. 

If on the MDM console the account addition blacklist is not set to blacklist all email domains, or on the Samsung Android device the user is able to add an account, this is a finding.)
  desc 'fix', %q(Configure Samsung Android to prevent users from adding personal email accounts to the work email app. 

Do one of the following: 
- Method #1: Allow users to only add DoD-approved email accounts to the work email app. 
- Method #2: Disallow users from adding any email accounts to the work email app and provision the users' email account on their behalf. 

**** 

Method #1: On the MDM console, for the device, in the "Knox account" group, add all DoD-approved email domains to the account addition whitelist. 

Refer to the MDM documentation to determine if an account addition blacklist is also required to be configured when enforcing an account addition whitelist. 

**** 

Method #2: On the MDM console, for the device, do the following: 
1. In the "Knox account" group, blacklist all email domains in the account addition blacklist. 
2. Provision the user's email account for the work email app. 

Refer to the MDM documentation to determine how to provision users' work email accounts for the work email app.)
  impact 0.5
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COBO KPE(Legacy)'
  tag check_id: 'C-92271r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92953'
  tag rid: 'SV-103041r1_rule'
  tag stig_id: 'KNOX-09-000015'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-99199r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
