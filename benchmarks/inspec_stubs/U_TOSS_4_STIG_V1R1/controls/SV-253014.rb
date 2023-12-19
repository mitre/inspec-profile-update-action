control 'SV-253014' do
  title 'Successful/unsuccessful uses of the fchown system call in TOSS must generate an audit record.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The "fchown" system call is used to change the ownership of a file referred to by the open file descriptor.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1." The AUID representation is an unsigned 32-bit integer, which equals "4294967295." The audit system interprets "-1", "4294967295", and "unset" in the same way.

'
  desc 'check', 'Verify TOSS generates an audit record when successful/unsuccessful attempts to use the "fchown" system call by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w fchown /etc/audit/audit.rules

-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=unset -k perm_mod

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "fchown" system call by adding or updating the following line to "/etc/audit/rules.d/audit.rules": 

-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=unset -k perm_mod

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56467r824364_chk'
  tag severity: 'medium'
  tag gid: 'V-253014'
  tag rid: 'SV-253014r824366_rule'
  tag stig_id: 'TOSS-04-030610'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-56417r824365_fix'
  tag satisfies: ['SRG-OS-000064-GPOS-00033', 'SRG-OS-000462-GPOS-00206']
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
