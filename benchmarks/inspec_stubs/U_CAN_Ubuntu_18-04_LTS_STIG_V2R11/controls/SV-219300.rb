control 'SV-219300' do
  title 'The Ubuntu operating system must generate audit records when successful/unsuccessful attempts to use the fdisk command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', %q(Verify if the Ubuntu operating system is configured to audit the execution of the partition management program "fdisk".

Check the currently configured audit rules with the following command:

# sudo auditctl -l | grep fdisk

-w /sbin/fdisk -p x -k fdisk

If the command does not return a line, or the line is commented out, this is a finding.

Note: The '-k' allows for specifying an arbitrary identifier and the string after it does not need to match the example output above.)
  desc 'fix', 'Configure the Ubuntu operating system to audit the execution of the partition management program "fdisk".

Add or update the following rule in the "/etc/audit/rules.d/stig.rules" file.

-w /sbin/fdisk -p x -k fdisk

Note: The root account must be used to view and/or edit any files in the /etc/audit/rules.d/ directory.

In order to reload the rules file, issue the following command:

# sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-21025r305228_chk'
  tag severity: 'medium'
  tag gid: 'V-219300'
  tag rid: 'SV-219300r902859_rule'
  tag stig_id: 'UBTU-18-010392'
  tag gtitle: 'SRG-OS-000477-GPOS-00222'
  tag fix_id: 'F-21024r902858_fix'
  tag 'documentable'
  tag legacy: ['V-100823', 'SV-109927']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
