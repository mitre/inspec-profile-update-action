control 'SV-38442' do
  title 'All accounts on the system must have unique user or account names.'
  desc 'A unique user name is the first part of the identification and authentication process. If user names are not unique, there can be no accountability on the system for auditing purposes. Multiple accounts sharing the same name could result in the Denial of Service to one or both of the accounts or unauthorized access to files or privileges.'
  desc 'check', 'Verify the consistency of the assigned home directories in the authentication database.

For Trusted Mode:
# authck -av

For SMSE:
# pwck

If any duplicate account names are found, this is a finding.'
  desc 'fix', 'Determine if the duplicate accounts have the same or different UIDs.
# cat /etc/passwd | cut -f 1,1 -d “:” | sort | uniq -d

If the UIDs are different, the account name must be changed. If the UIDs are the same, disable/remove one of the two (or more) password file entries via the SAM/SMH interface.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36245r4_chk'
  tag severity: 'medium'
  tag gid: 'V-761'
  tag rid: 'SV-38442r2_rule'
  tag stig_id: 'GEN000300'
  tag gtitle: 'GEN000300'
  tag fix_id: 'F-31502r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-2, IAIA-1'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
