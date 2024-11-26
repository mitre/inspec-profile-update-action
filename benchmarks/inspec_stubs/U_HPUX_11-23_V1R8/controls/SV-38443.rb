control 'SV-38443' do
  title 'All accounts must be assigned unique User Identification Numbers (UIDs).'
  desc "Accounts sharing a UID have full access to each others' files. This has the same effect as sharing a login. There is no way to assure identification, authentication, and accountability because the system sees them as the same user. If the duplicate UID is 0, this gives potential intruders another privileged account to attack."
  desc 'check', 'Verify the consistency of the assigned home directories in the authentication database.
For Trusted Mode:
# authck -av

For SMSE:
# pwck

If a non-unique UID is found in the password file, this is a finding.'
  desc 'fix', 'Determine if the duplicate UIDs are associated with the same or a different account name.
# cat /etc/passwd | grep <non-uniqueUID>

or, for multiple non-unique UIDs:
# cat /etc/passwd | egrep “<non-uniqueUID1>|<non-uniqueUID2>|,non-uniqueUIDn>“

If the account names are unique, the UIDs must also be modified to be unique. If the account names are the same, disable/remove one of the two (or more) password file entries via the SAM/SMH interface.
.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36246r2_chk'
  tag severity: 'medium'
  tag gid: 'V-762'
  tag rid: 'SV-38443r2_rule'
  tag stig_id: 'GEN000320'
  tag gtitle: 'GEN000320'
  tag fix_id: 'F-31503r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
