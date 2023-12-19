control 'SV-254134' do
  title 'Nutanix AOS must provide audit record generation capability for DoD-defined auditable events for successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels).'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the operating system will provide an audit record generation capability as: Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels).'
  desc 'check', 'Confirm Nutanix AOS is configured to generate audit records on all successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels).

$ sudo grep -w "postdrop" /etc/audit/audit.rules
-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

$ sudo grep -w "postqueue" /etc/audit/audit.rules
-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

$ sudo grep -w "semanage" /etc/audit/audit.rules
-a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=4294967295 -k secobjects

$ sudo grep -w "setfiles" /etc/audit/audit.rules
-a always,exit -F path=/usr/sbin/setfiles -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change

$ sudo grep -w "userhelper" /etc/audit/audit.rules
-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd

$ sudo grep -w "setsebool" /etc/audit/audit.rules
-a always,exit -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=4294967295 -k secobjects

$ sudo grep -w "unix_chkpwd" /etc/audit/audit.rules
-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

$ sudo grep -w faillock /etc/audit/audit.rules
-w /var/run/faillock/ -p wa -k logins

$ sudo grep -w lastlog /etc/audit/audit.rules
-w /var/log/lastlog -p wa -k logins

If the command(s) does not return the appropriate response line, as indicated above, or if the line(s) is commented out, this is a finding.'
  desc 'fix', 'Configure the audit rules by running the following command:

$ sudo salt-call state.sls security/CVM/auditCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57619r846488_chk'
  tag severity: 'medium'
  tag gid: 'V-254134'
  tag rid: 'SV-254134r846800_rule'
  tag stig_id: 'NUTX-OS-000270'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-57570r846489_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
