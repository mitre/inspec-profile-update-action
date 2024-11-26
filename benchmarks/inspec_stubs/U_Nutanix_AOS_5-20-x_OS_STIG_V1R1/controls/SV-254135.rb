control 'SV-254135' do
  title 'Nutanix AOS must provide audit record generation capability for DoD-defined auditable events for system and account management actions.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the operating system will provide an audit record generation capability as: Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system.'
  desc 'check', 'Confirm Nutanix AOS auditing is configured to generate audit records for all access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system.

$ sudo yum list installed audit
Installed Packages
audit.x86_64 

$ sudo grep -w chcon /etc/audit/audit.rules
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -k secobjects

$ sudo grep ssh-agent /etc/audit/audit.rules
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

$ sudo grep -w /usr/bin/mount /etc/audit/audit.rules
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

$ sudo grep -w /usr/bin/umount /etc/audit/audit.rules
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

$ sudo grep ssh-keysign /etc/audit/audit.rules
-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

$ sudo grep -w pam_timestamp_check /etc/audit/audit.rules
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

$ sudo grep -w crontab /etc/audit/audit.rules
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

$ sudo grep -w chsh /etc/audit/audit.rules
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

If the command(s) does not return the appropriate response line, as indicated above, or if the line(s) is commented out, this is a finding.'
  desc 'fix', 'Configure the audit rules by running the following command:

$ sudo salt-call state.sls security/CVM/auditCVMI18:J21N18I18:J22I18:J22N18I18:J22I18:J23N18I18:J22I18:J24N18I18:J22I18:J25N18II18:J22'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57620r846491_chk'
  tag severity: 'medium'
  tag gid: 'V-254135'
  tag rid: 'SV-254135r846493_rule'
  tag stig_id: 'NUTX-OS-000280'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-57571r846492_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
