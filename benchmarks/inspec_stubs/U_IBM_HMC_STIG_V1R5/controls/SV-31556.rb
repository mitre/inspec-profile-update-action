control 'SV-31556' do
  title 'Audit records content must contain valid information to allow for proper incident reporting.'
  desc 'The content of audit data must validate that the information contains:
 
User IDs
Successful and unsuccessful attempts to access security files (e.g., audit records, password files, access control files, etc)
Date and time of the event
Type of event
Success or failure of event
Successful and unsuccessful logons
Denial of access resulting from excessive number of logon attempts
Failure to not contain this information may hamper attempts to trace events and not allow proper tracking of incidents during a forensic investigation'
  desc 'check', 'Have the System Administrator validate the audit records contain valid information to allow for a proper incident tracking. Use the View Console Events task to display contents of security logs. 

Use the View Console Events task to view security logs and validate that it has the following information:

User IDs
Successful and unsuccessful attempts to access security files (e.g., audit records, password files, access control files, etc)
Date and time of the event
Type of event
Success or failure of event
Successful and unsuccessful logons
Denial of access resulting from excessive number of logon attempts'
  desc 'fix', 'Have the System Administrator check the content of audit records.

Use the View Console Events task to view security logs and validate that it has the following information:

User IDs
Successful and unsuccessful attempts to access security files (e.g., audit records, password files, access control files, etc)
Date and time of the event
Type of event
Success or failure of event
Successful and unsuccessful logons
Denial of access resulting from excessive number of logon attempts'
  impact 0.5
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-31829r1_chk'
  tag severity: 'medium'
  tag gid: 'V-25387'
  tag rid: 'SV-31556r2_rule'
  tag stig_id: 'HMC0185'
  tag gtitle: 'HMC0185'
  tag fix_id: 'F-28329r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2'
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-001487']
  tag nist: ['AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 f']
end
