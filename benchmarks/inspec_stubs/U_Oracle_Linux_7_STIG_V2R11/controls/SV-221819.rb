control 'SV-221819' do
  title 'The Oracle Linux operating system must audit all uses of the pam_timestamp_check command.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

When a user logs on, the auid is set to the uid of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals 4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.'
  desc 'check', 'Verify the operating system generates audit records when successful/unsuccessful attempts to use the "pam_timestamp_check" command occur. 

Check the auditing rules in "/etc/audit/audit.rules" with the following command:

$ sudo grep -w "/usr/sbin/pam_timestamp_check" /etc/audit/audit.rules

-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=unset -k privileged-pam 

If the command does not return any output, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when successful/unsuccessful attempts to use the "pam_timestamp_check" command occur. 

Add or update the following rule in "/etc/audit/rules.d/audit.rules": 

-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=unset -k privileged-pam

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23534r833092_chk'
  tag severity: 'medium'
  tag gid: 'V-221819'
  tag rid: 'SV-221819r833094_rule'
  tag stig_id: 'OL07-00-030810'
  tag gtitle: 'SRG-OS-000471-GPOS-00215'
  tag fix_id: 'F-23523r833093_fix'
  tag 'documentable'
  tag legacy: ['V-99377', 'SV-108481']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
