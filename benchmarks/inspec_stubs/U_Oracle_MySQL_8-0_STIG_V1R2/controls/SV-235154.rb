control 'SV-235154' do
  title 'The MySQL Database Server 8.0 must maintain the authenticity of communications sessions by guarding against man-in-the-middle attacks that guess at Session ID values.'
  desc 'One class of man-in-the-middle, or session hijacking, attack involves the adversary guessing at valid session identifiers based on patterns in identifiers already known.

The preferred technique for thwarting guesses at Session IDs is the generation of unique session identifiers using a FIPS 140-2 approved random number generator.

However, it is recognized that available DBMS products do not all implement the preferred technique yet may have other protections against session hijacking. Therefore, other techniques are acceptable, provided they are demonstrated to be effective.'
  desc 'check', %q(Determine if MySQL is configured to require SSL.  

SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME like 'require_secure_transport';

If require_secure_transport is not "ON", this is a finding.

Determine if MySQL is configured to require the use of FIPS compliant algorithms. 

SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME = 'ssl_fips_mode';

If ssl_fips_mode is not "ON", this is a finding.)
  desc 'fix', 'Connect as a mysql administrator 
mysql> set persist require_secure_transport=ON;

Turn on MySQL FIPS mode (ON or STRICT)  and restart mysqld
Edit my.cnf
[mysqld]
ssl_fips_mode=ON
or
ssl_fips_mode=STRICT'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38373r623582_chk'
  tag severity: 'medium'
  tag gid: 'V-235154'
  tag rid: 'SV-235154r623584_rule'
  tag stig_id: 'MYS8-00-007000'
  tag gtitle: 'SRG-APP-000224-DB-000384'
  tag fix_id: 'F-38336r623583_fix'
  tag 'documentable'
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
