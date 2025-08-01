control 'SV-204551' do
  title 'The Red Hat Enterprise Linux operating system must audit all uses of the chsh command.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged access commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.

When a user logs on, the auid is set to the uid of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals 4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.

'
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the "chsh" command occur.

Check that the following system call is being audited by performing the following command to check the file system rules in "/etc/audit/audit.rules": 

# grep -i /usr/bin/chsh /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/chsh -F auid>=1000 -F auid!=unset -k privileged-priv_change

If the command does not return any output, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use the "chsh" command occur.

Add or update the following rule in "/etc/audit/rules.d/audit.rules": 

-a always,exit -F path=/usr/bin/chsh -F auid>=1000 -F auid!=unset -k privileged-priv_change

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4675r462648_chk'
  tag severity: 'medium'
  tag gid: 'V-204551'
  tag rid: 'SV-204551r603261_rule'
  tag stig_id: 'RHEL-07-030720'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-4675r462649_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag legacy: ['SV-86791', 'V-72167']
  tag cci: ['CCI-000172', 'CCI-000135', 'CCI-000130', 'CCI-002884']
  tag nist: ['AU-12 c', 'AU-3 (1)', 'AU-3 a', 'MA-4 (1) (a)']
end
