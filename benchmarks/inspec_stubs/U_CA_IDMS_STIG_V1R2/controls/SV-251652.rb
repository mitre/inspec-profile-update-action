control 'SV-251652' do
  title 'The DBMS must develop a procedure to limit the number of concurrent sessions to an organization-defined number per user for all accounts and/or account types.'
  desc 'Database management includes the ability to control the number of users and user sessions utilizing a DBMS. Unlimited concurrent connections to the DBMS could allow a successful Denial of Service (DoS) attack by exhausting connection resources; and a system can also fail or be degraded by an overload of legitimate users. Limiting the number of concurrent sessions per user is helpful in reducing these risks.

This requirement addresses concurrent session control for a single account. It does not address concurrent sessions by a single user via multiple system accounts; and it does not deal with the total number of sessions across all accounts.

The capability to limit the number of concurrent sessions per user must be configured in or added to the DBMS (for example, by use of a logon trigger), when this is technically feasible. Note that it is not sufficient to limit sessions via a web server or application server alone, because legitimate users and adversaries can potentially connect to the DBMS by other means.

The organization will need to define the maximum number of concurrent sessions by account type, by account, or a combination thereof. In deciding on the appropriate number, it is important to consider the work requirements of the various types of users. For example, two might be an acceptable limit for general users accessing the database via an application; but 10 might be too few for a database administrator using a database management GUI tool, where each query tab and navigation pane may count as a separate session.

(Sessions may also be referred to as connections or logons, which for the purposes of this requirement are synonyms.)'
  desc 'check', 'Consult the system DBA and review system procedures for measures that establish a dataset to be used as a lock file.

If there is no such procedure, this is a finding.'
  desc 'fix', 'Require users to use specific JCL that includes exclusive access to a dataset used as a lock file. This would prevent more than one job from running at a time. 

This would not allow multiple users to have one session active at a time, this would be one active session, no matter how many individual users are attempting to run the batch jobs. 

The CA IDMS DBA must develop a Journal Analyzer procedure for authorized users to capture, record, and log all content related to a user.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55087r807821_chk'
  tag severity: 'medium'
  tag gid: 'V-251652'
  tag rid: 'SV-251652r807823_rule'
  tag stig_id: 'IDMS-DB-000910'
  tag gtitle: 'SRG-APP-000001-DB-000031'
  tag fix_id: 'F-55041r807822_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
