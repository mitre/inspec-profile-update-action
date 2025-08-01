control 'SV-99055' do
  title 'The SLES for vRealize audit system must be configured to audit all attempts to alter the system through sethostname.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the SLES for vRealize is capable of generating audit records.

DoD has defined the list of events for which the SLES for vRealize will provide an audit record generation capability as the following: 

1) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

2) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system;

3) All account creations, modifications, disabling, and terminations; and 

4) All kernel module load, unload, and restart actions.'
  desc 'check', 'Check if SLES for vRealize is configured to audit calls to the "sethostname" system call, run the following command:

# grep -w "sethostname" /etc/audit/audit.rules

If SLES for vRealize is configured to audit this activity, it will return at least one line. If no line is returned, this is a finding.'
  desc 'fix', "Run the following command:

# echo '-a exit,always -F arch=b64 -S sethostname' >> /etc/audit/audit.rules

Or run the following command to implement all logging requirements:

# /etc/dodscript.sh"
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88097r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88405'
  tag rid: 'SV-99055r1_rule'
  tag stig_id: 'VROM-SL-000205'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-95147r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
