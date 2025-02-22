control 'SV-96593' do
  title 'MongoDB must maintain the authenticity of communications sessions by guarding against man-in-the-middle attacks that guess at Session ID values.'
  desc 'One class of man-in-the-middle, or session hijacking, attack involves the adversary guessing at valid session identifiers based on patterns in identifiers already known.

The preferred technique for thwarting guesses at Session IDs is the generation of unique session identifiers using a FIPS 140-2 approved random number generator.

However, it is recognized that available DBMS products do not all implement the preferred technique yet may have other protections against session hijacking. Therefore, other techniques are acceptable, provided they are demonstrated to be effective.'
  desc 'check', 'Check the MongoDB configuration file (default location: /etc/mongod.conf).

The following should be set:

net:
ssl:
mode: requireSSL

If this is not found in the MongoDB configuration file, this is a finding.'
  desc 'fix', 'Follow the documentation guide at https://docs.mongodb.com/v3.4/tutorial/configure-ssl/.

Stop/start (restart) and mongod or mongos using the MongoDB configuration file.'
  impact 0.5
  ref 'DPMS Target MongoDB 3.x'
  tag check_id: 'C-81671r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81879'
  tag rid: 'SV-96593r1_rule'
  tag stig_id: 'MD3X-00-000410'
  tag gtitle: 'SRG-APP-000224-DB-000384'
  tag fix_id: 'F-88729r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
