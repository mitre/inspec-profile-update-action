control 'SV-208888' do
  title 'The operating system must automatically audit account modification.'
  desc 'In addition to auditing new user and group accounts, these watches will alert the system administrator(s) to any modifications. Any unexpected users, groups, or modifications should be investigated for legitimacy.'
  desc 'check', %q(To determine if the system is configured to audit account changes, run the following command:

$sudo egrep -w '(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/security/opasswd)' /etc/audit/audit.rules

If the system is configured to watch for account changes, lines should be returned for each file specified (and with "-p wa" for each).

If the system is not configured to audit account changes, this is a finding.)
  desc 'fix', 'Add the following to "/etc/audit/audit.rules", in order to capture events that modify account changes: 

# audit_account_changes
-w /etc/group -p wa -k audit_account_changes
-w /etc/passwd -p wa -k audit_account_changes
-w /etc/gshadow -p wa -k audit_account_changes
-w /etc/shadow -p wa -k audit_account_changes
-w /etc/security/opasswd -p wa -k audit_account_changes'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9141r357644_chk'
  tag severity: 'low'
  tag gid: 'V-208888'
  tag rid: 'SV-208888r793673_rule'
  tag stig_id: 'OL6-00-000175'
  tag gtitle: 'SRG-OS-000239'
  tag fix_id: 'F-9141r357645_fix'
  tag 'documentable'
  tag legacy: ['SV-65283', 'V-51077']
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
