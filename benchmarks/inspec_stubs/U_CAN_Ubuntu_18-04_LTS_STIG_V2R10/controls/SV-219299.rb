control 'SV-219299' do
  title 'The Ubuntu operating system must generate audit records when successful/unsuccessful attempts to use the kmod command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', %q(Verify if the Ubuntu operating system is configured to audit the execution of the module management program "kmod".

Check the currently configured audit rules with the following command:

# sudo auditctl -l | grep kmod

-w /bin/kmod -p x -k module

If the command does not return a line, or the line is commented out, this is a finding.

Note: The '-k' allows for specifying an arbitrary identifier and the string after it does not need to match the example output above.)
  desc 'fix', 'Configure the Ubuntu operating system to audit the execution of the module management program "kmod".

Add or update the following rule in the "/etc/audit/rules.d/stig.rules" file.

-w /bin/kmod -p x -k modules

Note:
The "root" account must be used to view/edit any files in the /etc/audit/rules.d/ directory.

In order to reload the rules file, issue the following command:

# sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-21024r305225_chk'
  tag severity: 'medium'
  tag gid: 'V-219299'
  tag rid: 'SV-219299r610963_rule'
  tag stig_id: 'UBTU-18-010391'
  tag gtitle: 'SRG-OS-000477-GPOS-00222'
  tag fix_id: 'F-21023r305226_fix'
  tag 'documentable'
  tag legacy: ['SV-109925', 'V-100821']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
