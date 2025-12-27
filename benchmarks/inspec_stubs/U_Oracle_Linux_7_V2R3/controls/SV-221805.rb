control 'SV-221805' do
  title 'The Oracle Linux operating system must audit all uses of the gpasswd command.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged password commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.

When a user logs on, the auid is set to the uid of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals 4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.

'
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the "gpasswd" command occur.

Check the file system rule in "/etc/audit/audit.rules" with the following command:

# grep -i /usr/bin/gpasswd /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/gpasswd -F auid>=1000 -F auid!=unset -k privileged-passwd

If the command does not return any output, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use the "gpasswd" command occur.

Add or update the following rule in "/etc/audit/rules.d/audit.rules":

-a always,exit -F path=/usr/bin/gpasswd -F auid>=1000 -F auid!=unset -k privileged-passwd

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23520r419487_chk'
  tag severity: 'medium'
  tag gid: 'V-221805'
  tag rid: 'SV-221805r603260_rule'
  tag stig_id: 'OL07-00-030650'
  tag gtitle: 'SRG-OS-000042-GPOS-00020'
  tag fix_id: 'F-23509r419488_fix'
  tag satisfies: ['SRG-OS-000042-GPOS-00020', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag legacy: ['SV-108453', 'V-99349']
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
