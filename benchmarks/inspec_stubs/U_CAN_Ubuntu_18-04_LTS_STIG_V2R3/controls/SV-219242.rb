control 'SV-219242' do
  title 'The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the ssh-agent command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', %q(Verify the Ubuntu operating system generates an audit record when successful/unsuccessful attempts to use the "ssh-agent" command occur.

Check the configured audit rules with the following commands:

# sudo auditctl -l | grep '/usr/bin/ssh-agent'

-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-ssh

If the command does not return lines that match the example or the lines are commented out, this is a finding.

Note: The '-k' allows for specifying an arbitrary identifier and the string after it does not need to match the example output above.)
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "ssh-agent" command. 

Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file:

-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-ssh

In order to reload the rules file, issue the following command:

# sudo augenrules --load 

Note:
The "root" account must be used to view/edit any files in the /etc/audit/rules.d/ directory.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-20967r305054_chk'
  tag severity: 'medium'
  tag gid: 'V-219242'
  tag rid: 'SV-219242r610963_rule'
  tag stig_id: 'UBTU-18-010319'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-20966r305055_fix'
  tag 'documentable'
  tag legacy: ['V-100711', 'SV-109815']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
