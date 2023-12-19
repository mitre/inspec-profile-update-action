control 'SV-89123' do
  title 'DB2 must include additional, more detailed, organization-defined information in the audit records for audit events identified by type, location, or subject.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. To support analysis, some types of events will need information to be logged that exceeds the basic requirements of event type, time stamps, location, source, outcome, and user identity. If additional information is not available, it could negatively impact forensic investigations into user actions or other malicious events.

The organization must determine what additional information is required for complete analysis of the audited events. The additional information required is dependent on the type of information (e.g., sensitivity of the data and the environment within which it resides). At a minimum, the organization must employ either full-text recording of privileged commands or the individual identities of group users, or both. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise. 

Examples of detailed information the organization may require in audit records are full-text recording of privileged commands or the individual identities of group account users.'
  desc 'check', 'Check with the ISSO if any more of the organization-defined information needs to be captured as part of DBMS auditing.

If there is additional information that needs to be captured and is currently not being written to audit logs, this is a finding.'
  desc 'fix', 'Configure the application to write the organization-defined information to a database table.

Set the auditing for the database table capturing the organization-defined information so that it is written to the database audit.

Define an audit policy with the needed subset using the CREATE AUDIT POLICY SQL statement:
DB2> CREATE AUDIT POLICY <table audit policy name> 
           CATEGORIES CONTEXT STATUS BOTH, EXECUTE STATUS BOTH 
           ERROR TYPE AUDIT

To modify an existing audit policy, replace "CREATE" with "ALTER" in the preceding statement. Only the categories explicitly named in the statement will be affected. In this case, the changes take effect immediately.

If CREATE was used above, apply the policy created to the database: 
DB2> AUDIT TABLE <org info table> using <audit policy name>'
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74375r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74449'
  tag rid: 'SV-89123r1_rule'
  tag stig_id: 'DB2X-00-001800'
  tag gtitle: 'SRG-APP-000101-DB-000044'
  tag fix_id: 'F-81049r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
