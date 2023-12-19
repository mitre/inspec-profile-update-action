control 'SV-93361' do
  title 'SQL stored queries or procedures installed during Tanium installation must be removed from the Tanium Server.'
  desc 'Failure to protect organizational information from data mining may result in a compromise of information.

Data storage objects include, for example, databases, database records, and database fields. Data mining prevention and detection techniques include, for example: limiting the types of responses provided to database queries; limiting the number/frequency of database queries to increase the work factor needed to determine the contents of such databases; and notifying organizational personnel when atypical database queries or accesses occur.'
  desc 'check', 'Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Navigate to Program Files >> Tanium >> Tanium Server.

If any SQL stored queries (.sql files) or procedures are found, this is a finding.'
  desc 'fix', 'Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Navigate to Program Files >> Tanium >> Tanium Server.

Remove the SQL stored queries (.sql files) or procedures from the folder.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78225r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78655'
  tag rid: 'SV-93361r1_rule'
  tag stig_id: 'TANS-DB-000006'
  tag gtitle: 'SRG-APP-000454'
  tag fix_id: 'F-85391r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
