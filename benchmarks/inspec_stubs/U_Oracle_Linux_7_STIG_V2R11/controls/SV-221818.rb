control 'SV-221818' do
  title 'The Oracle Linux operating system must audit all uses of the crontab command.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.

When a user logs on, the auid is set to the uid of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals 4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.

'
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the "crontab" command occur. 

Check that the following system call is being audited by performing the following command to check the file system rules in "/etc/audit/audit.rules": 

$ sudo grep -w "/usr/bin/crontab" /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=unset -k privileged-cron

If the command does not return any output, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use the "crontab" command occur. 

Add or update the following rule in "/etc/audit/rules.d/audit.rules": 

-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=unset -k privileged-cron

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23533r833089_chk'
  tag severity: 'medium'
  tag gid: 'V-221818'
  tag rid: 'SV-221818r833091_rule'
  tag stig_id: 'OL07-00-030800'
  tag gtitle: 'SRG-OS-000042-GPOS-00020'
  tag fix_id: 'F-23522r833090_fix'
  tag satisfies: ['SRG-OS-000042-GPOS-00020', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag legacy: ['V-99375', 'SV-108479']
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
