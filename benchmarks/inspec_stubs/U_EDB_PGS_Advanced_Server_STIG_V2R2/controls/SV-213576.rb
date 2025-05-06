control 'SV-213576' do
  title 'The EDB Postgres Advanced Server must include additional, more detailed, organization-defined information in the audit records for audit events identified by type, location, or subject.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. To support analysis, some types of events will need information to be logged that exceeds the basic requirements of event type, time stamps, location, source, outcome, and user identity. If additional information is not available, it could negatively impact forensic investigations into user actions or other malicious events.

The organization must determine what additional information is required for complete analysis of the audited events. The additional information required is dependent on the type of information (e.g., sensitivity of the data and the environment within which it resides). At a minimum, the organization must employ either full-text recording of privileged commands or the individual identities of group users, or both. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise. 

Examples of detailed information the organization may require in audit records are full-text recording of privileged commands or the individual identities of group account users.

In EnterpriseDB Postgres Plus Advanced Server, the edb_audit_tag can be used to record additional information.  This tag can be set to different values by different sessions (connections), and can be set to new values any number of times.  How to recognize the conditions for producing such audit data has to be determined and coded for as part of application and database design.'
  desc 'check', 'Review the system documentation to identify what additional information the organization has determined necessary.

Check application and database design, and existing audit records to verify that all organization-defined additional, more detailed information is in the audit records for audit events identified by type, location, or subject.

If any additional information is defined and is not included in the audit records, this is a finding.'
  desc 'fix', "Execute the following SQL to set additional detailed information for the audit records in the session:

set edb_audit_tag = '<information>';

Replace <information> with a character string holding the additional data that must be captured.

To set this in a trigger, an example is included below.  Keep in mind that the edb_audit_tag is set for the life of the session, not just the life of the insert command:

CREATE OR REPLACE FUNCTION add_audit_info()
  RETURNS trigger AS
$BODY$
BEGIN
  SET edb_audit_tag = '<information>'; 
  RETURN NEW;
END;
$BODY$
LANGUAGE plpgsql;

CREATE TRIGGER add_audit_info_trigger
  BEFORE INSERT
  ON <table>
  FOR EACH ROW
  EXECUTE PROCEDURE add_audit_info();"
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14798r290040_chk'
  tag severity: 'medium'
  tag gid: 'V-213576'
  tag rid: 'SV-213576r508024_rule'
  tag stig_id: 'PPS9-00-002200'
  tag gtitle: 'SRG-APP-000101-DB-000044'
  tag fix_id: 'F-14796r290041_fix'
  tag 'documentable'
  tag legacy: ['SV-83511', 'V-68907']
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
