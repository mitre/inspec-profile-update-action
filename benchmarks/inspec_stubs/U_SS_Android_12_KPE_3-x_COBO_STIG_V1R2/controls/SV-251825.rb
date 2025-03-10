control 'SV-251825' do
  title 'Samsung Android must be configured to prevent users from adding personal email accounts to the work email app.'
  desc 'If the user is able to add a personal email account (POP3, IMAP, EAS) to the work email app, it could be used to forward sensitive DoD data to unauthorized recipients. Restricting email account addition to the Administrator or to allowlisted accounts mitigates this vulnerability.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are preventing users from adding personal email accounts to the work email app.

On the management tool, in the device restrictions section, verify "Modify accounts" is set to "Disallow".

On the Samsung Android device: 
1. Open Settings >> Accounts and backup >> Manage accounts.
2. Verify that no account can be added.

If on the management tool "Modify accounts" is not set to "Disallow", or on the Samsung Android device an account can be added, this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to prevent users from adding personal email accounts to the work email app.

On the management tool, in the device restrictions, set "Modify accounts" to "Disallow".'
  impact 0.5
  ref 'DPMS Target Samsung Android 12 KPE 3.x COBO'
  tag check_id: 'C-55285r814229_chk'
  tag severity: 'medium'
  tag gid: 'V-251825'
  tag rid: 'SV-251825r814231_rule'
  tag stig_id: 'KNOX-12-110230'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-55239r814230_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
