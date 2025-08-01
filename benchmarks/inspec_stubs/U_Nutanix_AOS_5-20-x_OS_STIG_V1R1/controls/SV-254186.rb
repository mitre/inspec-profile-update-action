control 'SV-254186' do
  title 'Nutanix AOS audit tools must be group-owned by root.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user has in order to make access decisions regarding the deletion of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Verify the audit tools are group-owned by "root" to prevent any unauthorized access, deletion, or modification.

Check the owner of each audit tool by running the following commands:
$ sudo stat -c "%G %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules
[sudo] password for admin: 
root /sbin/auditctl
root /sbin/aureport
root /sbin/ausearch
root /sbin/autrace
root /sbin/auditd
root /sbin/rsyslogd
root /sbin/augenrules

If any of the audit tools are not group-owned by "root", this is a finding.'
  desc 'fix', 'Configure the audit tools to be group-owned by "root", by running the following command:

$ sudo chgrp root [audit_tool]

Replace "[audit_tool]" with each audit tool not group-owned by "root".'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57671r846644_chk'
  tag severity: 'medium'
  tag gid: 'V-254186'
  tag rid: 'SV-254186r846646_rule'
  tag stig_id: 'NUTX-OS-000980'
  tag gtitle: 'SRG-OS-000258-GPOS-00099'
  tag fix_id: 'F-57622r846645_fix'
  tag 'documentable'
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']
end
