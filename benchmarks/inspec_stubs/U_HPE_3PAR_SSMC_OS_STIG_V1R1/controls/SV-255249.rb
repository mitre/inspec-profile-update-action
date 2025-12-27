control 'SV-255249' do
  title 'SSMC must provide audit record generation capability for DOD-defined auditable events for all operating system components.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DOD has defined the list of events for which the operating system will provide an audit record generation capability as the following: 

1. Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

2. Access actions, such as successful and unsuccessful logon attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logons from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system;

3. All account creations, modifications, disabling, and terminations; and 

4. All kernel module load, unload, and restart actions.

'
  desc 'check', 'Verify that SSMC provides audit record generation capability for DOD-defined auditable events for all operating system components, by executing the following command:

$ sudo /ssmc/bin/config_security.sh -o verbose_shell_session_logs -a status

Verbose shell session log is enabled

If the command outputs do not read as "enabled", this is a finding.'
  desc 'fix', 'Configure SSMC to provide audit record generation capability for DOD-defined auditable events for all operating system components by executing the following command:

$ sudo /ssmc/bin/config_security.sh -o verbose_shell_session_logs -a enable -f'
  impact 0.3
  ref 'DPMS Target HPE 3PAR SSMC OS'
  tag check_id: 'C-58862r869895_chk'
  tag severity: 'low'
  tag gid: 'V-255249'
  tag rid: 'SV-255249r869897_rule'
  tag stig_id: 'SSMC-OS-030050'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-58806r869896_fix'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172']
  tag 'documentable'
  tag cci: ['CCI-000169', 'CCI-002884']
  tag nist: ['AU-12 a', 'MA-4 (1) (a)']
end
