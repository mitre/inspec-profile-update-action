control 'SV-209067' do
  title 'The system must provide automated support for account management functions.'
  desc 'A comprehensive account management process that includes automation helps to ensure the accounts designated as requiring attention are consistently and promptly addressed. Enterprise environments make user account management challenging and complex. A user management process requiring administrators to manually address account management functions adds risk of potential oversight.'
  desc 'check', 'Interview the SA to determine if there is an automated system for managing user accounts, preferably integrated with an existing enterprise user management system.

If there is not, this is a finding.'
  desc 'fix', 'Implement an automated system for managing user accounts that minimizes the risk of errors, either intentional or deliberate.  If possible, this system should integrate with an existing enterprise user management system, such as, one based Active Directory or Kerberos.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9320r357986_chk'
  tag severity: 'medium'
  tag gid: 'V-209067'
  tag rid: 'SV-209067r793788_rule'
  tag stig_id: 'OL6-00-000524'
  tag gtitle: 'SRG-OS-000001'
  tag fix_id: 'F-9320r357987_fix'
  tag 'documentable'
  tag legacy: ['SV-64725', 'V-50519']
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
