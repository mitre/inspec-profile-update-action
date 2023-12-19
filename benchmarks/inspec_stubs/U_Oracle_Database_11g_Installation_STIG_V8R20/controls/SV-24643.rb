control 'SV-24643' do
  title 'DBMS tools or applications that echo or require a password entry in clear text should be protected from password display.'
  desc 'Database applications may allow for entry of the account name and password as a visible parameter of the application execution command. This practice should be prohibited and disabled, if possible, by the application. If it cannot be disabled, then users should be strictly instructed not to use this feature. Typically, the application will prompt for this information and accept it without echoing it on the users computer screen.'
  desc 'check', 'Review policy and instructions included or noted in the System Security Plan used to inform users and administrators not to enter database passwords at the command line.

Review documented and implemented procedures used to monitor the DBMS system for such activity.

If policy or instructions do not exist, proof of users and administrators being briefed does not exist or monitoring for compliance is not being performed to dissuade the practice of entering database passwords on the command line, this is a Finding.'
  desc 'fix', 'Review policy and instructions included or noted in the System Security Plan used to inform users and administrators not to enter database passwords at the command line.

Review documented and implemented procedures used to monitor the DBMS system for such activity.

If policy or instructions do not exist, proof of users and administrators being briefed does not exist or monitoring for compliance is not being performed to dissuade the practice of entering database passwords on the command line, this is a Finding.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29167r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3813'
  tag rid: 'SV-24643r1_rule'
  tag stig_id: 'DG0068-ORACLE11'
  tag gtitle: 'DBMS application password display'
  tag fix_id: 'F-26179r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
