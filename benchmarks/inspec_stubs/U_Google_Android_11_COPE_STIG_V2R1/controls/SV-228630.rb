control 'SV-228630' do
  title 'The Google Android 11 Work Profile must be configured to prevent users from adding personal email accounts to the work email app.'
  desc 'If the user is able to add a personal email account (POP3, IMAP, EAS) to the work email app, it could be used to forward sensitive DoD data to unauthorized recipients. Restricting email account addition to the administrator or restricting email account addition to allow listed accounts mitigates this vulnerability.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review the Google Android 11 Work Profile configuration settings to confirm that users are prevented from adding personal email accounts to the work email app. 
 
This procedure is performed on both the EMM Administrator console and the Google Android 11 device. 
 
On the EMM console:
1. Open "Set user restrictions".
2. Verify that "Disallow modify accounts" is toggled to On.

On the Google Android 11 device, do the following: 
1. Open Settings. 
2. Tap "Accounts". 
3. Verify that "Add account" is grayed out under the Work section.
 
If on the EMM console the restriction to "Disallow modify accounts" is not set, or on the Google Android 11 device the user is able to add an account in the Work section, this is a finding.'
  desc 'fix', %q(Configure Google Android 11 device to prevent users from adding personal email accounts to the work email app. 
 
On the EMM console: 
1. Open "Set user restrictions".
2. Toggle "Disallow modify accounts" to On.

Refer to the EMM documentation to determine how to provision users' work email accounts for the work email app.)
  impact 0.5
  ref 'DPMS Target Google Android 11 COPE'
  tag check_id: 'C-30865r505887_chk'
  tag severity: 'medium'
  tag gid: 'V-228630'
  tag rid: 'SV-228630r619923_rule'
  tag stig_id: 'GOOG-11-009200'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-30842r505888_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
