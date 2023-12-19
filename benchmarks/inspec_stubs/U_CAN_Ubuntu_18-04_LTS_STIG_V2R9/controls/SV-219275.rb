control 'SV-219275' do
  title 'The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the usermod command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', %q(Verify that an audit event is generated for any successful/unsuccessful use of the "usermod" command.

Check the currently configured audit rules with the following command:

# sudo auditctl -l | grep -w usermod

-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-usermod

If the command does not return a line that matches the example or the line is commented out, this is a finding.

Note: The '-k' allows for specifying an arbitrary identifier and the string after it does not need to match the example output above.)
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "usermod" command. 

Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file:

-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-usermod

Note:
The "root" account must be used to view/edit any files in the /etc/audit/rules.d/ directory.

In order to reload the rules file, issue the following command:

# sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-21000r305153_chk'
  tag severity: 'medium'
  tag gid: 'V-219275'
  tag rid: 'SV-219275r610963_rule'
  tag stig_id: 'UBTU-18-010352'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-20999r305154_fix'
  tag 'documentable'
  tag legacy: ['SV-109879', 'V-100775']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
