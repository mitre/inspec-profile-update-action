control 'SV-44807' do
  title 'All accounts on the system must have unique user or account names.'
  desc 'A unique user name is the first part of the identification and authentication process.  If user names are not unique, there can be no accountability on the system for auditing purposes.  Multiple accounts sharing the same name could result in the denial of service to one or both of the accounts or unauthorized access to files or privileges.'
  desc 'check', 'Check the system for duplicate account names.

Example:
# pwck -r

If any duplicate account names are found, this is a finding.'
  desc 'fix', 'Change user account names, or delete accounts, so each account has a unique name.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42294r1_chk'
  tag severity: 'medium'
  tag gid: 'V-761'
  tag rid: 'SV-44807r1_rule'
  tag stig_id: 'GEN000300'
  tag gtitle: 'GEN000300'
  tag fix_id: 'F-38252r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
