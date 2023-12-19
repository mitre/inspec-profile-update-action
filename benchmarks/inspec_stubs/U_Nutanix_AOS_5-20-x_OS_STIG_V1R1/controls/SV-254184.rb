control 'SV-254184' do
  title 'Nutanix AOS audit tools must be configured to 0755 or less permissive.'
  desc 'Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.'
  desc 'check', 'Verify the audit tools are protected from unauthorized access, deletion, or modification by checking the permissive mode.

Check the octal permission of each audit tool by running the following command:
$ sudo stat -c "%a %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules
750 /sbin/auditctl
750 /sbin/aureport
750 /sbin/ausearch
750 /sbin/autrace
750 /sbin/auditd
755 /sbin/rsyslogd
755 /sbin/augenrules

If any of the audit tools has a mode more permissive than "0755", this is a finding.'
  desc 'fix', 'Configure the audit tools to be protected from unauthorized access by setting the correct permissive mode using the following command:

$ sudo chmod 0755 [audit_tool]

Replace "[audit_tool]" with the audit tool that does not have the correct permissive mode.'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57669r846638_chk'
  tag severity: 'medium'
  tag gid: 'V-254184'
  tag rid: 'SV-254184r846640_rule'
  tag stig_id: 'NUTX-OS-000960'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag fix_id: 'F-57620r846639_fix'
  tag 'documentable'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
