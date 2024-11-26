control 'SV-234981' do
  title 'The SUSE operating system must not disable syscall auditing.'
  desc 'By default, the SUSE operating system includes the "-a task,never" audit rule as a default. This rule suppresses syscall auditing for all tasks started with this rule in effect. Because the audit daemon processes the "audit.rules" file from the top down, this rule supersedes all other defined syscall rules; therefore no syscall auditing can take place on the operating system.'
  desc 'check', 'Verify syscall auditing has not been disabled:

> auditctl -l | grep -i "a task,never"

If any results are returned, this is a finding.

Verify the default rule "-a task,never" is not statically defined :

> grep -rv "^#" /etc/audit/rules.d/ | grep -i "a task,never"

If any results are returned, this is a finding.'
  desc 'fix', 'Remove the "-a task,never" rule from the /etc/audit/rules.d/audit.rules file.

The audit daemon must be restarted for the changes to take effect.

> sudo systemctl restart auditd.service'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38169r619212_chk'
  tag severity: 'medium'
  tag gid: 'V-234981'
  tag rid: 'SV-234981r622137_rule'
  tag stig_id: 'SLES-15-030820'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38132r619213_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
