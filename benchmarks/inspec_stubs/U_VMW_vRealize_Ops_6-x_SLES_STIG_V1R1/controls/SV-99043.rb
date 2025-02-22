control 'SV-99043' do
  title 'The SLES for vRealize audit system must be configured to audit all administrative, privileged, and security actions.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the operating system will provide an audit record generation capability as the following: 

1) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

2) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system;

3) All account creations, modifications, disabling, and terminations; and 

4) All kernel module load, unload, and restart actions.'
  desc 'check', 'Check the auditing configuration of the system:

# cat /etc/audit/audit.rules | grep -i "auditd.conf" 

If no results are returned, or the line does not start with "-w", this is a finding.

Expected Result:
-w /etc/audit/auditd.conf'
  desc 'fix', %q(Add the following lines to the "audit.rules" file to enable auditing of administrative, privileged, and security actions:

echo '-w /etc/audit/auditd.conf' >> /etc/audit/audit.rules

Or run the following command to implement all logging requirements:

# /etc/dodscript.sh)
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88085r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88393'
  tag rid: 'SV-99043r1_rule'
  tag stig_id: 'VROM-SL-000175'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-95135r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
