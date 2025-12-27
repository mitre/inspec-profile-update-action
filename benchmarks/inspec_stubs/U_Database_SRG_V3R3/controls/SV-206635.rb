control 'SV-206635' do
  title 'The DBMS must generate audit records when concurrent logons/connections by the same user from different workstations occur.'
  desc 'For completeness of forensic analysis, it is necessary to track who logs on to the DBMS.

Concurrent connections by the same user from multiple workstations may be valid use of the system; or such connections may be due to improper circumvention of the requirement to use the CAC for authentication; or they may indicate unauthorized account sharing; or they may be because an account has been compromised.

(If the fact of multiple, concurrent logons by a given user can be reliably reconstructed from the log entries for other events (logons/connections; voluntary and involuntary disconnections), then it is not mandatory to create additional log entries specifically for this.)'
  desc 'check', 'Review the DBMS audit settings. 

If the fact of multiple, concurrent logons by a given user (or other principal) can be reliably reconstructed from the log entries for other events, then this is not a finding.

If an audit record is not generated each time a user (or other principal) who is already connected to the DBMS logs on or connects to the DBMS from a different workstation, this is a finding.'
  desc 'fix', 'Configure DBMS audit settings to generate an audit record each time a user (or other principal) who is already connected to the DBMS logs on or connects to the DBMS from a different workstation.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6895r291573_chk'
  tag severity: 'medium'
  tag gid: 'V-206635'
  tag rid: 'SV-206635r617447_rule'
  tag stig_id: 'SRG-APP-000506-DB-000353'
  tag gtitle: 'SRG-APP-000506'
  tag fix_id: 'F-6895r291574_fix'
  tag 'documentable'
  tag legacy: ['SV-72543', 'V-58113']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
