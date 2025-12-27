control 'SV-230781' do
  title "The macOS system must allocate audit record storage capacity to store at least one week's worth of audit records when audit records are not immediately sent to a central audit record storage facility."
  desc 'The audit service must be configured to require that records are kept for seven days or longer before deletion when there is no central audit record storage facility. When "expire-after" is set to "7d", the audit service will not delete audit logs until the log data is at least seven days old.'
  desc 'check', 'The check displays the amount of time the audit system is configured to retain audit log files. The audit system will not delete logs until the specified condition has been met. To view the current setting, run the following command:

/usr/bin/sudo /usr/bin/grep ^expire-after /etc/security/audit_control

If this returns no results, or does not contain "7d" or a larger value, this is a finding.'
  desc 'fix', %q(Edit the "/etc/security/audit_control" file and change the value for "expire-after" to the amount of time audit logs should be kept for the system. Use the following command to set the "expire-after" value to "7d":

/usr/bin/sudo /usr/bin/sed -i.bak 's/.*expire-after.*/expire-after:7d/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s

A text editor may also be used to implement the required updates to the "/etc/security/audit_control" file.)
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33726r607230_chk'
  tag severity: 'medium'
  tag gid: 'V-230781'
  tag rid: 'SV-230781r877391_rule'
  tag stig_id: 'APPL-11-001029'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-33699r607593_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
