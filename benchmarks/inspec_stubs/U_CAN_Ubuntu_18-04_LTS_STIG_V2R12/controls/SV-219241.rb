control 'SV-219241' do
  title 'The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the umount command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', %q(Verify if the Ubuntu operating system generates audit records when successful/unsuccessful attempts to use of the "umount" command occur.

Check the configured audit rules with the following commands:

# sudo auditctl -l | grep '/bin/umount'

-a always,exit -F path=/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-umount

If the command does not return lines that match the example or the lines are commented out, this is a finding.

Note: The '-k' allows for specifying an arbitrary identifier and the string after it does not need to match the example output above.)
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "umount" command. 

Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file:

-a always,exit -F path=/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-umount

In order to reload the rules file, issue the following command:

# sudo augenrules --load 

Note:
The "root" account must be used to view/edit any files in the /etc/audit/rules.d/ directory.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-20966r305051_chk'
  tag severity: 'medium'
  tag gid: 'V-219241'
  tag rid: 'SV-219241r610963_rule'
  tag stig_id: 'UBTU-18-010318'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-20965r305052_fix'
  tag 'documentable'
  tag legacy: ['SV-109813', 'V-100709']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
