control 'SV-215246' do
  title 'AIX must provide audit record generation functionality for DoD-defined auditable events.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records.

DoD has defined the list of events for which AIX will provide an audit record generation capability as the following: 

1) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security levels, or categories of information (e.g., classification levels);

2) Access actions, such as successful and unsuccessful login attempts, privileged activities or other system-level access, starting and ending time for user access to the system, concurrent logins from different workstations, successful and unsuccessful accesses to objects, all program initiations, and all direct access to the information system;

3) All account creations, modifications, disabling, and terminations; and 

4) All kernel module load, unload, and restart actions.

'
  desc 'check', 'Ensure that auditing is properly configured.

Run the "stig_audit_check.sh" script.

If any results are returned from the script, this is a finding.

Verify that the file "/etc/security/audit/objects" includes the following objects:

/etc/security/environ:
w = "S_ENVIRON_WRITE"

/etc/security/group:
w = "S_GROUP_WRITE"

/etc/group: 
w = "S_GROUP_WRITE"

/etc/security/limits:
w = "S_LIMITS_WRITE"

/etc/security/login.cfg:
w = "S_LOGIN_WRITE"

/etc/security/passwd:
r = "S_PASSWD_READ"
w = "S_PASSWD_WRITE"

/etc/security/user:
w = "S_USER_WRITE"

/etc/security/audit/config:
w = "AUD_CONFIG_WR"

If any of the objects listed above are missing from "/etc/security/audit/objects", this is a finding.'
  desc 'fix', 'Use the "stig_audit_config.txt" file to configure the AIX audit process.

Edit the /etc/security/audit/objects file and add or update the following lines to the listed values:

/etc/security/environ:
    w = "S_ENVIRON_WRITE"

/etc/security/group:
    w = "S_GROUP_WRITE"

/etc/group: 
    w = "S_GROUP_WRITE"

/etc/security/limits:
    w = "S_LIMITS_WRITE"

/etc/security/login.cfg:
    w = "S_LOGIN_WRITE"

/etc/security/passwd:
    r = "S_PASSWD_READ"
    w = "S_PASSWD_WRITE"

/etc/security/user:
    w = "S_USER_WRITE"

/etc/security/audit/config:
    w = "AUD_CONFIG_WR"


Restart the audit process:
# /usr/sbin/audit shutdown
# /usr/sbin/audit start

Note: There are multiple default "classes" defined in the "/etc/security/audit/config" file. The only audit class that is required by this document is the "stig_aud_class". All other defined classes can be removed at the discretion of the organization.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16444r364821_chk'
  tag severity: 'medium'
  tag gid: 'V-215246'
  tag rid: 'SV-215246r508663_rule'
  tag stig_id: 'AIX7-00-002016'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-16442r294190_fix'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000004-GPOS-00004', 'SRG-OS-000051-GPOS-00024', 'SRG-OS-000064-GPOS-00033', 'SRG-OS-000239-GPOS-00089', 'SRG-OS-000240-GPOS-00090', 'SRG-OS-000241-GPOS-00091', 'SRG-OS-000277-GPOS-00107', 'SRG-OS-000303-GPOS-00120', 'SRG-OS-000304-GPOS-00121', 'SRG-OS-000327-GPOS-00127', 'SRG-OS-000327-GPOS-00127', 'SRG-OS-000364-GPOS-00151', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000461-GPOS-00205', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000463-GPOS-00207', 'SRG-OS-000465-GPOS-00209', 'SRG-OS-000466-GPOS-00210', 'SRG-OS-000467-GPOS-00211', 'SRG-OS-000468-GPOS-00212', 'SRG-OS-000470-GPOS-00214', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000471-GPOS-00216', 'SRG-OS-000472-GPOS-00217', 'SRG-OS-000473-GPOS-00218', 'SRG-OS-000474-GPOS-00219', 'SRG-OS-000475-GPOS-00220', 'SRG-OS-000476-GPOS-00221', 'SRG-OS-000477-GPOS-00222']
  tag 'documentable'
  tag legacy: ['V-91775', 'SV-101873']
  tag cci: ['CCI-000169', 'CCI-000154', 'CCI-000018', 'CCI-000172', 'CCI-001813', 'CCI-001686', 'CCI-002130', 'CCI-002132', 'CCI-001403', 'CCI-001404', 'CCI-001405', 'CCI-002234', 'CCI-002884']
  tag nist: ['AU-12 a', 'AU-6 (4)', 'AC-2 (4)', 'AU-12 c', 'CM-5 (1) (a)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-6 (9)', 'MA-4 (1) (a)']
end
