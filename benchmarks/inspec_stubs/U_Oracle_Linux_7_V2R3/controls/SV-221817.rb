control 'SV-221817' do
  title 'The Oracle Linux operating system must audit all uses of the ssh-keysign command.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged ssh commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.

When a user logs on, the auid is set to the uid of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals 4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.

'
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the "ssh-keysign" command occur. 

Check that the following system call is being audited by performing the following command to check the file system rules in "/etc/audit/audit.rules": 

# grep -iw /usr/libexec/openssh/ssh-keysign /etc/audit/audit.rules

-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F auid>=1000 -F auid!=unset -k privileged-ssh

If the command does not return any output, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use the "ssh-keysign" command occur. 

Add or update the following rule in "/etc/audit/rules.d/audit.rules": 

-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F auid>=1000 -F auid!=unset -k privileged-ssh

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23532r419523_chk'
  tag severity: 'medium'
  tag gid: 'V-221817'
  tag rid: 'SV-221817r603260_rule'
  tag stig_id: 'OL07-00-030780'
  tag gtitle: 'SRG-OS-000042-GPOS-00020'
  tag fix_id: 'F-23521r419524_fix'
  tag satisfies: ['SRG-OS-000042-GPOS-00020', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag legacy: ['SV-108477', 'V-99373']
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
