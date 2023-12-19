control 'SV-258490' do
  title 'The Google Android 13 work profile must be configured to prevent users from adding personal email accounts to the work email app.'
  desc 'If the user can add a personal email account (POP3, IMAP, EAS) to the work email app, it could be used to forward sensitive DOD data to unauthorized recipients. Restricting email account addition to the administrator or restricting email account addition to allowlisted accounts mitigates this vulnerability.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review the managed Google Android 13 work profile configuration settings to confirm that users are prevented from adding personal email accounts to the work email app. 
 
This procedure is performed on both the EMM Administrator console and the managed Google Android 13 device. 
 
On the EMM console:

1. Open "Set user restrictions".
2. Verify "Disallow modify accounts" is toggled to "ON".

On the managed Google Android 13 device: 

1. Open Settings.
2. Tap "Passwords & accounts".
3. Select "Work".
4. Tap "Add account".
5. Verify a message is displayed to the user stating, "Blocked by your IT admin".
 
If on the EMM console the restriction to "Disallow modify accounts" is not set, or on the managed Android 13 device the user is able to add an account in the Work section, this is a finding.'
  desc 'fix', %q(Configure the Google Android 13 device to prevent users from adding personal email accounts to the work email app. 
 
On the EMM console: 

1. Open "Set user restrictions".
2. Toggle "Disallow modify accounts" to "ON".

Refer to the EMM documentation to determine how to provision users' work email accounts for the work email app.)
  impact 0.5
  ref 'DPMS Target Google Android 13 BYOAD'
  tag check_id: 'C-62230r929284_chk'
  tag severity: 'medium'
  tag gid: 'V-258490'
  tag rid: 'SV-258490r929286_rule'
  tag stig_id: 'GOOG-13-710100'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62139r929285_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
