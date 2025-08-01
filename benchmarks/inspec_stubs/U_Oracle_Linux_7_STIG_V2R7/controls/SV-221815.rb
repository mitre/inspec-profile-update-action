control 'SV-221815' do
  title 'The Oracle Linux operating system must audit all uses of the postdrop command.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged postfix commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.

When a user logs on, the auid is set to the uid of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals 4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.

'
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the "postdrop" command occur.

Check that the following system call is being audited by performing the following command to check the file system rules in "/etc/audit/audit.rules": 

# grep -iw /usr/sbin/postdrop /etc/audit/audit.rules

-a always,exit -F path=/usr/sbin/postdrop -F auid>=1000 -F auid!=unset -k privileged-postfix

If the command does not return any output, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use the "postdrop" command occur.

Add or update the following rule in "/etc/audit/rules.d/audit.rules": 

-a always,exit -F path=/usr/sbin/postdrop -F auid>=1000 -F auid!=unset -k privileged-postfix

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23530r419517_chk'
  tag severity: 'medium'
  tag gid: 'V-221815'
  tag rid: 'SV-221815r603260_rule'
  tag stig_id: 'OL07-00-030760'
  tag gtitle: 'SRG-OS-000042-GPOS-00020'
  tag fix_id: 'F-23519r419518_fix'
  tag satisfies: ['SRG-OS-000042-GPOS-00020', 'SRG-OS-000392-GPOS-00172']
  tag 'documentable'
  tag legacy: ['SV-108473', 'V-99369']
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
