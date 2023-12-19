control 'SV-219243' do
  title 'The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the ssh-keysign command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', %q(Verify the Ubuntu operating system generates an audit record when successful/unsuccessful attempts to use the "ssh-keysign" command occur.

Check the configured audit rules with the following commands:

#sudo auditctl -l | grep ssh-keysign

-a always,exit -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-ssh

If the command does not return lines that match the example or the lines are commented out, this is a finding.

Note: The '-k' allows for specifying an arbitrary identifier and the string after it does not need to match the example output above.)
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "ssh-keysign" command. 

Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file:

-a always,exit -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-ssh

In order to reload the rules file, issue the following command:

# sudo augenrules --load 

Note:
The "root" account must be used to view/edit any files in the /etc/audit/rules.d/ directory.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-20968r305057_chk'
  tag severity: 'medium'
  tag gid: 'V-219243'
  tag rid: 'SV-219243r610963_rule'
  tag stig_id: 'UBTU-18-010320'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-20967r305058_fix'
  tag 'documentable'
  tag legacy: ['V-100713', 'SV-109817']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
