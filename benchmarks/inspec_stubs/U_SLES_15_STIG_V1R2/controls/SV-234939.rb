control 'SV-234939' do
  title 'The SUSE operating system must generate audit records for all uses of the modprobe command.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the following list of events for which the SUSE operating system will provide an audit record generation capability: 

1) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

2) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system;

3) All account creations, modifications, disabling, and terminations; and 

4) All kernel module load, unload, and restart actions.

'
  desc 'check', %q(Verify the SUSE operating system generates an audit record for all uses of the "modprobe" command.

Check that the command is being audited by performing the following command:

> sudo auditctl -l | grep -w '/sbin/modprobe'

-w /sbin/modprobe -p x -k modules

If the system is configured to audit the execution of the module management program "modprobe", the command will return a line. 

If the command does not return a line, this is a finding.

Note:
The "-k" allows for specifying an arbitrary identifier. The string following "-k" does not need to match the example output above.)
  desc 'fix', 'Configure the SUSE operating system to audit the execution of the module management program "modprobe" by adding the following line to "/etc/audit/rules.d/audit.rules":

-w /sbin/modprobe -p x -k modules 

To reload the rules file, restart the audit daemon

> sudo systemctl restart auditd.service

or issue the following command:

> sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38127r619086_chk'
  tag severity: 'medium'
  tag gid: 'V-234939'
  tag rid: 'SV-234939r622137_rule'
  tag stig_id: 'SLES-15-030400'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-38090r619087_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag cci: ['CCI-000169', 'CCI-000130', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-12 a', 'AU-3 a', 'AU-12 c', 'MA-4 (1) (a)']
end
