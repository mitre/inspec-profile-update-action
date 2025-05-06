control 'SV-252164' do
  title 'MongoDB must maintain the authenticity of communications sessions by guarding against man-in-the-middle attacks that guess at Session ID values.'
  desc 'One class of man-in-the-middle, or session hijacking, attack involves the adversary guessing at valid session identifiers based on patterns in identifiers already known.

The preferred technique for thwarting guesses at Session IDs is the generation of unique session identifiers using a FIPS 140-2-approved random number generator.

However, it is recognized that available DBMS products do not all implement the preferred technique yet may have other protections against session hijacking. Therefore, other techniques are acceptable, provided they are demonstrated to be effective.'
  desc 'check', 'Check the MongoDB configuration file (default location: /etc/mongod.conf).

The following option must  be present (net.tls.mode) and set to requireTLS:

net:
   tls:
      mode: requireTLS

If this is not found in the MongoDB configuration file, this is a finding.'
  desc 'fix', 'Edit the %MongoDB configuration file% to ensure the net.tls.mode option is included and set to the value requireTLS as shown below:

net:
   tls:
      mode: requireTLS

Stop/start (restart) and mongod or mongos using the %MongoDB configuration file%.

Further documentation is here:
https://docs.mongodb.com/v4.4/tutorial/configure-ssl/.'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55620r817012_chk'
  tag severity: 'medium'
  tag gid: 'V-252164'
  tag rid: 'SV-252164r817013_rule'
  tag stig_id: 'MD4X-00-003700'
  tag gtitle: 'SRG-APP-000224-DB-000384'
  tag fix_id: 'F-55570r813873_fix'
  tag 'documentable'
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
