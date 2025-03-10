control 'SV-226443' do
  title 'All accounts on the system must have unique user or account names.'
  desc 'A unique user name is the first part of the identification and authentication process.  If user names are not unique, there can be no accountability on the system for auditing purposes.  Multiple accounts sharing the same name could result in the Denial of Service to one or both of the accounts or unauthorized access to files or privileges.'
  desc 'check', "Check the system for duplicate account names.

Example:
# passwd -sa | sort | uniq -c | awk '$1 > 1 {print $2}'

If any duplicate account names are found, this is a finding."
  desc 'fix', 'Change user account names, or delete accounts, so each account has a unique name.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28604r482696_chk'
  tag severity: 'medium'
  tag gid: 'V-226443'
  tag rid: 'SV-226443r603265_rule'
  tag stig_id: 'GEN000300'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-28592r482697_fix'
  tag 'documentable'
  tag legacy: ['SV-27061', 'V-761']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
