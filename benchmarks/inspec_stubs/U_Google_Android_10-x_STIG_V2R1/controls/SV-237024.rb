control 'SV-237024' do
  title 'The Google Android 10 Work Profile must be configured to prevent users from adding personal email accounts to the work email app.'
  desc 'If the user is able to add a personal email account (POP3, IMAP, EAS) to the work email app, it could be used to forward sensitive DoD data to unauthorized recipients. Restricting email account addition to the administrator or restricting email account addition to whitelisted accounts mitigates this vulnerability.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review the Google Android 10 Work Profile configuration settings to confirm that users are prevented from adding personal email accounts to the work email app. 

This procedure is performed on both the MDM Administrator console and the Google Android 10 device. 

On the MDM console:
1. Open User restrictions.
2. Verify that "Disallow modify accounts" is set to on.

On the Google Android 10 device, do the following: 
1. Open Settings. 
2. Tap "Accounts". 
3. Verify that "Add account" is grayed out under the Work section.

If on the MDM console the restriction to "Disallow modify accounts" is not set, or on the Google Android 10 device the user is able to add an account in the Work section, this is a finding.'
  desc 'fix', %q(Configure Google Android 10 Work Profile to prevent users from adding personal email accounts to the work email app. 

On the MDM console, for the Work Profile, do the following: 
1. Open User restrictions.
2. Set "Disallow modify accounts" to on.

Refer to the MDM documentation to determine how to provision users' work email accounts for the work email app.)
  impact 0.5
  ref 'DPMS Target Google Android 10-x'
  tag check_id: 'C-40243r639216_chk'
  tag severity: 'medium'
  tag gid: 'V-237024'
  tag rid: 'SV-237024r639218_rule'
  tag stig_id: 'GOOG-10-009200'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-40206r639217_fix'
  tag 'documentable'
  tag legacy: ['SV-108073', 'V-98969']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
