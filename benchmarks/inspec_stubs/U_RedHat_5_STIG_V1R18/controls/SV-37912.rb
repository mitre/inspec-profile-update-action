control 'SV-37912' do
  title 'System audit logs must be owned by root.'
  desc 'Failure to give ownership of system audit log files to root provides the designated owner and unauthorized users with the potential to access sensitive information.'
  desc 'check', 'Perform the following to determine the location of audit logs and then check the ownership.

Procedure:
# grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\\/]*//|xargs stat -c %U:%n

If any audit log file is not owned by root, this is a finding.'
  desc 'fix', 'Change the ownership of the audit log file(s).

Procedure:
# chown root <audit log file>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37138r1_chk'
  tag severity: 'medium'
  tag gid: 'V-812'
  tag rid: 'SV-37912r1_rule'
  tag stig_id: 'GEN002680'
  tag gtitle: 'GEN002680'
  tag fix_id: 'F-966r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECTP-1'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
