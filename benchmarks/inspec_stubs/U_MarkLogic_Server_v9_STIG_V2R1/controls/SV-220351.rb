control 'SV-220351' do
  title 'The audit information produced by MarkLogic Server must be protected from unauthorized deletion.'
  desc '<0> [object Object]'
  desc 'check', 'Review controls and permissions are sufficient to protect audit log files from unauthorized access at the operating-system level.

Verify User ownership, Group ownership, and permissions on the "audit" file:
> ls -al /var/opt/MarkLogic/Logs/AuditLog.txt

If the User owner is not "daemon", this is a finding
If the Group owner is not "daemon", this is a finding.
If the directory is more permissive than 700, this is a finding.'
  desc 'fix', 'Apply controls and modify permissions to protect audit log files from unauthorized access at the operating-system level.

Change owner and group of /var/opt/MarkLogic/Logs to user daemon from the command line with a privileged user:
> chown daemon.daemon /var/opt/MarkLogic/Logs

Change permissions of /var/opt/MarkLogic/Logs to 700 (rwx by owner only) from the command line
> chmod 700 /var/opt/MarkLogic/Logs'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22066r401504_chk'
  tag severity: 'medium'
  tag gid: 'V-220351'
  tag rid: 'SV-220351r622777_rule'
  tag stig_id: 'ML09-00-002100'
  tag gtitle: 'SRG-APP-000120-DB-000061'
  tag fix_id: 'F-22055r401505_fix'
  tag legacy: ['SV-110049', 'V-100945']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
