control 'SV-761' do
  title 'All accounts on the system must have unique user or account names.'
  desc 'A unique user name is the first part of the identification and authentication process. If user names are not unique, there can be no accountability on the system for auditing purposes. Multiple accounts sharing the same name could result in the Denial-of-Service to one or both of the accounts or unauthorized access to files or privileges.'
  desc 'check', 'Obtain a list of system accounts and check the list for any duplicate user names. If duplicates user names are found, this is a finding.'
  desc 'fix', 'Change user account names, or delete accounts, so each account has a unique name.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27976r1_chk'
  tag severity: 'medium'
  tag gid: 'V-761'
  tag rid: 'SV-761r2_rule'
  tag stig_id: 'GEN000300'
  tag gtitle: 'GEN000300'
  tag fix_id: 'F-24342r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
