control 'SV-253707' do
  title 'MariaDB must maintain the authenticity of communications sessions by guarding against man-in-the-middle attacks that guess at Session ID values.'
  desc 'Unique session IDs help to reduce predictability of said identifiers. Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions. 

When a user logs out, or when any other session termination event occurs, the DBMS must terminate the user session(s) to minimize the potential for sessions to be hijacked.'
  desc 'check', %q(Determine if MariaDB is configured to require SSL. 

MariaDB> SHOW GLOBAL VARIABLES LIKE 'require_secure_transport';

If require_secure_transport is not "ON", this is a finding.)
  desc 'fix', 'Modify the MariaDB configuration file located within /etc/my.cnf.d/ and set the variable require_secure_transport to "ON" under the server section. Restart MariaDB Enterprise Server. 

Example: 

[server]
require_secure_transport = ON'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57159r841644_chk'
  tag severity: 'medium'
  tag gid: 'V-253707'
  tag rid: 'SV-253707r841646_rule'
  tag stig_id: 'MADB-10-004900'
  tag gtitle: 'SRG-APP-000224-DB-000384'
  tag fix_id: 'F-57110r841645_fix'
  tag 'documentable'
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
