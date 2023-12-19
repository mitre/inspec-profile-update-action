control 'SV-230996' do
  title 'The Samsung Android Work Environment must be configured to prevent users from adding personal email accounts to the work email app.'
  desc 'If the user is able to add a personal email account (POP3, IMAP, EAS) to the work email app, it could be used to forward sensitive DoD data to unauthorized recipients. Restricting email account addition to the Administrator or to allowlisted accounts mitigates this vulnerability.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', %q(Review Samsung Android Work Environment configuration settings to determine if users are prevented from adding personal email accounts to the work email app.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool:
1. In the Work Environment restrictions section, set "Account Management" to "Disable" for: Work email app.
2. Provision the user's email account on their behalf.

For COPE: On the Samsung Android device: 
1. Open Settings >> Work profile >> Accounts.
2. Verify that no account can be added.
3. Verify that the user's work email app has been provisioned with the work email account.

For COBO: On the Samsung Android device: 
1. Open Settings >> Accounts and backup >> Manage accounts.
2. Verify that no account can be added.
3. Verify that the user's Work email app has been provisioned with the work email account.

If on the management tool "Account Management" is not set to "Disable" for the Work email app, or on the Samsung Android device an account can be added, this is a finding.)
  desc 'fix', %q(Configure the Samsung Android Work Environment to prevent users from adding personal email accounts to the work email app.

Refer to the management tool documentation to determine how to provision users’ work email accounts for the work email app.

On the management tool:
1. In the Work Environment restrictions section, set "Account Management" to "Disable" for: Work email app.
2. Provision the user's email account on their behalf.)
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x AE'
  tag check_id: 'C-33926r592480_chk'
  tag severity: 'medium'
  tag gid: 'V-230996'
  tag rid: 'SV-230996r607691_rule'
  tag stig_id: 'KNOX-11-017300'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-33899r592481_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
