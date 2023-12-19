control 'SV-30881' do
  title 'Audit records should contain required information.'
  desc 'Complete forensically valuable data may be unavailable or accountability may be jeopardized when audit records do not contain sufficient information.'
  desc 'check', 'Review samples of the DBMS audit logs.

Compare to the required elements listed below:
- User ID.
- Successful and unsuccessful attempts to access security files
- Date and time of the event.
- Type of event.
- Success or failure of event.
- Successful and unsuccessful logons.
- Denial of access resulting from excessive number of logon attempts.
- Blocking or blacklisting a user ID, terminal or access port, and the reason for the action.
- Activities that might modify, bypass, or negate safeguards controlled by the system.
- Data required to audit the possible use of covert channel mechanisms.
- Privileged activities and other system-level access.
- Starting and ending time for access to the system.
- Security relevant actions associated with periods processing or the changing of security labels or categories of information.

If the elements listed above are not included in the audit logs at at minimum, this is a Finding.'
  desc 'fix', 'Configure audit settings to include the following list of elements in the audit logs at a minimum:
- User ID.
- Successful and unsuccessful attempts to access security files
- Date and time of the event.
- Type of event.
- Success or failure of event.
- Successful and unsuccessful logons.
- Denial of access resulting from excessive number of logon attempts.
- Blocking or blacklisting a user ID, terminal or access port, and the reason for the action.
- Activities that might modify, bypass, or negate safeguards controlled by the system.
- Data required to audit the possible use of covert channel mechanisms.
- Privileged activities and other system-level access.
- Starting and ending time for access to the system.
- Security relevant actions associated with periods processing or the changing of security labels or categories of information.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-31301r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15646'
  tag rid: 'SV-30881r1_rule'
  tag stig_id: 'DG0145-ORACLE11'
  tag gtitle: 'DBMS audit record content'
  tag fix_id: 'F-27769r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
