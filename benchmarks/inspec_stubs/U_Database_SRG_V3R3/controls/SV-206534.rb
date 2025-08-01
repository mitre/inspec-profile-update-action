control 'SV-206534' do
  title 'The DBMS must include additional, more detailed, organization-defined information in the audit records for audit events identified by type, location, or subject.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. To support analysis, some types of events will need information to be logged that exceeds the basic requirements of event type, time stamps, location, source, outcome, and user identity. If additional information is not available, it could negatively impact forensic investigations into user actions or other malicious events.

The organization must determine what additional information is required for complete analysis of the audited events. The additional information required is dependent on the type of information (e.g., sensitivity of the data and the environment within which it resides). At a minimum, the organization must employ either full-text recording of privileged commands or the individual identities of users of shared accounts, or both. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise. 

Examples of detailed information the organization may require in audit records are full-text recording of privileged commands or the individual identities of shared account users.'
  desc 'check', 'Review the system documentation to identify what additional information the organization has determined to be necessary.

Check DBMS settings and existing audit records to verify that all organization-defined additional, more detailed information is in the audit records for audit events identified by type, location, or subject.

If any additional information is defined and is not contained in the audit records, this is a finding.'
  desc 'fix', 'Configure DBMS audit settings to include all organization-defined detailed information in the audit records for audit events identified by type, location, or subject.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6794r291270_chk'
  tag severity: 'medium'
  tag gid: 'V-206534'
  tag rid: 'SV-206534r617447_rule'
  tag stig_id: 'SRG-APP-000101-DB-000044'
  tag gtitle: 'SRG-APP-000101'
  tag fix_id: 'F-6794r291271_fix'
  tag 'documentable'
  tag legacy: ['SV-42712', 'V-32375']
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
