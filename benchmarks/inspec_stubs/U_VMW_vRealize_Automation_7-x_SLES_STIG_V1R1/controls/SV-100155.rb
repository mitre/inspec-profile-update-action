control 'SV-100155' do
  title 'The SLES for vRealize audit system must be configured to audit all attempts to alter system time through adjtimex.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which the operating system will provide an audit record generation capability as the following: 

1) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

2) Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system;

3) All account creations, modifications, disabling, and terminations; and 

4) All kernel module load, unload, and restart actions.'
  desc 'check', 'Check if the system is configured to audit calls to the "adjtimex" system call by running the following command:

# grep -w "adjtimex" /etc/audit/audit.rules

If the system is configured to audit time changes, it will return at least two lines containing "-S adjtimex" that also contain "arch=b64". 

If no line is returned, this is a finding.'
  desc 'fix', "Run the following command:

echo '-a exit,always -F arch=b64 -S adjtimex -F auid=0' >> /etc/audit/audit.rules
echo '-a exit,always -F arch=b64 -S adjtimex -F auid>=500 -F auid!=4294967295' >> /etc/audit/audit.rules

Or run the following command to implement all logging requirements:

# /etc/dodscript.sh"
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89197r2_chk'
  tag severity: 'medium'
  tag gid: 'V-89505'
  tag rid: 'SV-100155r1_rule'
  tag stig_id: 'VRAU-SL-000180'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-96247r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
