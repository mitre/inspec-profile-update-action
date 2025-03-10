control 'SV-231037' do
  title 'The Samsung Android Work Environment must be configured to prevent users from adding personal email accounts to the work email app.'
  desc 'If the user is able to add a personal email account (POP3, IMAP, EAS) to the work email app, it could be used to forward sensitive DoD data to unauthorized recipients. Restricting email account addition to the Administrator or to allowlisted accounts mitigates this vulnerability.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', %q(Review Samsung Android Work Environment configuration settings to determine if users are prevented from adding personal email accounts to the work email app.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool:
1. In the Work Environment Account section, set "Account Addition Denylist" to "Denylist all" for: Work email app.
2. Provision the user's email account on their behalf.

For COPE: On the Samsung Android device: 
1. Open Settings >> Work profile >> Accounts.
2. Verify that no account can be added.
3. Verify that the user's work email app has been provisioned with the work email account.

For COBO: On the Samsung Android device: 
1. Open Settings >> Accounts and backup >> Manage accounts.
2. Verify that no account can be added.
3. Verify that the user's work email app has been provisioned with the work email account.

If on the management tool "Account Addition Denylist" is not set to "Denylist all" for the Work email app, or on the Samsung Android device an account can be added, this is a finding.)
  desc 'fix', %q(Configure the Samsung Android Work Environment to prevent users from adding personal email accounts to the work email app.

Refer to the management tool documentation to determine how to provision users’ work email accounts for the work email app.

On the management tool:
1. In the Work Environment Account section, set "Account Addition Denylist" to "Denylist all" for: Work email app.
2. Provision the user's email account on their behalf.)
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x Legacy'
  tag check_id: 'C-33967r592725_chk'
  tag severity: 'medium'
  tag gid: 'V-231037'
  tag rid: 'SV-231037r608683_rule'
  tag stig_id: 'KNOX-11-017400'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-33940r592726_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
