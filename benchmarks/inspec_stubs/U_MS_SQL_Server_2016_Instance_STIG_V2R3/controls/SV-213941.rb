control 'SV-213941' do
  title 'SQL Server must include additional, more detailed, organization-defined information in the audit records for audit events identified by type, location, or subject.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information. To support analysis, some types of events will need information to be logged that exceeds the basic requirements of event type, time stamps, location, source, outcome, and user identity. If additional information is not available, it could negatively impact forensic investigations into user actions or other malicious events. 
 
The organization must determine what additional information is required for complete analysis of the audited events. The additional information required is dependent on the type of information (e.g., sensitivity of the data and the environment within which it resides). At a minimum, the organization must employ either full-text recording of privileged commands or the individual identities of users of shared accounts, or both. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.  
 
Examples of detailed information the organization may require in audit records are full-text recording of privileged commands or the individual identities of shared account users.'
  desc 'check', 'If a SQL Server Audit is not in use for audit purposes, this is a finding unless a third-party product is being used that can perform detailed auditing for SQL Server. 
 
Review system documentation to determine whether SQL Server is required to audit any events, and any fields, in addition to those in the standard audit.  
 
If there are none specified, this is not a finding.  
 
If SQL Server Audit is in use, compare the audit specification(s) with the documented requirements.  
 
If any such requirement is not satisfied by the audit specification(s) (or by supplemental, locally-deployed mechanisms), this is a finding.'
  desc 'fix', 'Design and deploy an Audit that captures all auditable events and data items. In the event a third-party tool is used for auditing it must contain all the required information including but not limited to events, type, location, subject, date and time and by whom the change occurred. 
 
Implement additional custom audits to capture the additional organizational required information.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15158r313606_chk'
  tag severity: 'medium'
  tag gid: 'V-213941'
  tag rid: 'SV-213941r617437_rule'
  tag stig_id: 'SQL6-D0-005500'
  tag gtitle: 'SRG-APP-000101-DB-000044'
  tag fix_id: 'F-15156r313607_fix'
  tag 'documentable'
  tag legacy: ['SV-93851', 'V-79145']
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
