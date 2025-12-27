control 'SV-217959' do
  title 'The operating system must automatically audit account termination.'
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
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19440r376892_chk'
  tag severity: 'low'
  tag gid: 'V-217959'
  tag rid: 'SV-217959r603264_rule'
  tag stig_id: 'RHEL-06-000177'
  tag gtitle: 'SRG-OS-000241'
  tag fix_id: 'F-19438r376893_fix'
  tag 'documentable'
  tag legacy: ['V-38538', 'SV-50339']
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
