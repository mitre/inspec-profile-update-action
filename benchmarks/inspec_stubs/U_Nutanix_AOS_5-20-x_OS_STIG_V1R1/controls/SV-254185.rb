control 'SV-254185' do
  title 'Nutanix AOS audit tools must be owned by root.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user has to make access decisions regarding the modification of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Verify the audit tools are owned by "root" to prevent any unauthorized access, deletion, or modification.

Check the owner of each audit tool by running the following commands:
$ sudo stat -c "%U %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules
[sudo] password for admin: 
root /sbin/auditctl
root /sbin/aureport
root /sbin/ausearch
root /sbin/autrace
root /sbin/auditd
root /sbin/rsyslogd
root /sbin/augenrules

If any of the audit tools are not owned by "root", this is a finding.'
  desc 'fix', 'Configure the audit tools to be owned by "root", by running the following command:

$ sudo chown root [audit_tool]

Replace "[audit_tool]" with each audit tool not owned by "root".'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57670r846641_chk'
  tag severity: 'medium'
  tag gid: 'V-254185'
  tag rid: 'SV-254185r846643_rule'
  tag stig_id: 'NUTX-OS-000970'
  tag gtitle: 'SRG-OS-000257-GPOS-00098'
  tag fix_id: 'F-57621r846642_fix'
  tag 'documentable'
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
