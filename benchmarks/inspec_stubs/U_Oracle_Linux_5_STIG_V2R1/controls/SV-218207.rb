control 'SV-218207' do
  title 'All accounts on the system must have unique user or account names.'
  desc 'A unique user name is the first part of the identification and authentication process.  If user names are not unique, there can be no accountability on the system for auditing purposes.  Multiple accounts sharing the same name could result in the denial of service to one or both of the accounts or unauthorized access to files or privileges.'
  desc 'check', 'Check the system for duplicate account names.

Example:
# pwck -r

If any duplicate account names are found, this is a finding.'
  desc 'fix', 'Change user account names, or delete accounts, so each account has a unique name.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19682r561407_chk'
  tag severity: 'medium'
  tag gid: 'V-218207'
  tag rid: 'SV-218207r603259_rule'
  tag stig_id: 'GEN000300'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-19680r561408_fix'
  tag 'documentable'
  tag legacy: ['V-761', 'SV-63251']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
