control 'SV-82273' do
  title 'SQL Server must include organization-defined additional, more detailed information in Trace or Audit records for events identified by type, location, or subject.'
  desc 'SQL Server auditing capability is critical for accurate forensic analysis. Audit record content which may be necessary to satisfy the requirement of this control includes:  time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, file names involved, and access control or flow control rules invoked.

SQL Server does have a means available to add organizationally defined additional, more detailed information in the audit event records. These events may be identified by type, location, or subject. An example of more detailed information the organization may require in audit records could be the name of the application where the request is coming from.

Some organizations may determine that more detailed information is required for specific database event types. If this information is not available, it could negatively impact forensic investigations into user actions or other malicious events.

Use of SQL Server Audit is recommended.  All features of SQL Server Audit are available in the Enterprise and Developer editions of SQL Server 2014.  It is not available at the database level in other editions.  For this or legacy reasons, the instance may be using SQL Server Trace for auditing, which remains an acceptable solution for the time being.  Note, however, that Microsoft intends to remove most aspects of Trace at some point after SQL Server 2016.'
  desc 'check', 'If neither SQL Server Audit nor SQL Server Trace is in use for audit purposes, this is a finding.

Review system documentation to determine whether SQL Server is required to audit any events, and any fields, in addition to those in the standard audit or audit-oriented trace.

If there are none specified, this is not a finding.

If SQL Server Trace is in use for audit purposes, review the audit-oriented trace definition script(s) to identify any events and/or fields that are required but not in the script.

If any such are identified, this is a finding.

If SQL Server Audit is in use, compare the audit specification(s) with the documented requirements.

If any such requirement is not satisfied by the audit specification(s) (or by supplemental, locally-deployed mechanisms), this is a finding.'
  desc 'fix', "If Trace is in use for audit purposes, where SQL Server's trace facilities can provide the necessary data, define and enable a trace that captures all organization-defined auditable events and fields.  The script provided in the supplemental file Trace.sql can be used for this, after appropriate editing.

Where SQL Server's trace facilities cannot provide the necessary data, designate the event code(s) that will be used (Microsoft provides codes 82 through 91 for this purpose), design and deploy triggers that will recognize the events and invoke sp_trace_generateevent to populate the trace with the necessary information.  Add a block of sp_trace_setevent calls to the trace script for each event code designated for this purpose.

If SQL Server Audit is in use, design and deploy an Audit that captures all auditable events and data items.  The script provided in the supplemental file Audit.sql can be used as the basis for this.  Supplement the standard audit data as necessary, using database audit specifications, Extended Events and/or triggers."
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2014'
  tag check_id: 'C-68351r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67783'
  tag rid: 'SV-82273r1_rule'
  tag stig_id: 'SQL4-00-012400'
  tag gtitle: 'SRG-APP-000101-DB-000044'
  tag fix_id: 'F-73899r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
