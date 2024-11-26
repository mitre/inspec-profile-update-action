control 'SV-217217' do
  title 'The SUSE operating system must generate audit records for all uses of the kmod command.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the following list of events for which the SUSE operating system will provide an audit record generation capability: 

1) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

2) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system;

3) All account creations, modifications, disabling, and terminations; and 

4) All kernel module load, unload, and restart actions.

'
  desc 'check', 'Verify the SUSE operating system generates an audit record for all uses of the "kmod" command.

Check that the following command call is being audited by performing the following command on the system rules in "/etc/audit/audit.rules":

# sudo grep kmod /etc/audit/audit.rules

-w /usr/bin/kmod -p x -k modules

If the system is configured to audit the execution of the module management program "kmod", the command will return a line. 

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to audit the execution of the module management program "kmod" by adding the following line to "/etc/audit/rules.d/audit.rules":

-w /usr/bin/kmod -p x -k modules

The audit daemon must be restarted for any changes to take effect.  
 
# sudo systemctl restart auditd.service'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18445r369807_chk'
  tag severity: 'medium'
  tag gid: 'V-217217'
  tag rid: 'SV-217217r603262_rule'
  tag stig_id: 'SLES-12-020360'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-18443r369808_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag legacy: ['V-77347', 'SV-92043']
  tag cci: ['CCI-000169', 'CCI-000172', 'CCI-000130', 'CCI-002884']
  tag nist: ['AU-12 a', 'AU-12 c', 'AU-3 a', 'MA-4 (1) (a)']
end
