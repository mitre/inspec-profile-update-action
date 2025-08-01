control 'SV-206567' do
  title 'The DBMS must maintain the authenticity of communications sessions by guarding against man-in-the-middle attacks that guess at Session ID values.'
  desc 'One class of man-in-the-middle, or session hijacking, attack involves the adversary guessing at valid session identifiers based on patterns in identifiers already known.

The preferred technique for thwarting guesses at Session IDs is the generation of unique session identifiers using a FIPS 140-2 approved random number generator.

However, it is recognized that available DBMS products do not all implement the preferred technique yet may have other protections against session hijacking. Therefore, other techniques are acceptable, provided they are demonstrated to be effective.'
  desc 'check', 'Review DBMS vendor documentation and system behavior (and if necessary, consult vendor representatives) to determine whether the DBMS can provide demonstrably effective protection against man-in-the-middle attacks that guess at session identifier values.

If not, this is a finding.

Review DBMS settings to determine whether protections against man-in-the-middle attacks that guess at session identifier values are enabled.

If they are not, this is a finding.'
  desc 'fix', 'Utilize a DBMS product that can provide demonstrably effective protection against man-in-the-middle attacks that guess at session identifier values.

Configure DBMS settings to enable protections against man-in-the-middle attacks that guess at session identifier values.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6827r291369_chk'
  tag severity: 'medium'
  tag gid: 'V-206567'
  tag rid: 'SV-206567r617447_rule'
  tag stig_id: 'SRG-APP-000224-DB-000384'
  tag gtitle: 'SRG-APP-000224'
  tag fix_id: 'F-6827r291370_fix'
  tag 'documentable'
  tag legacy: ['SV-72595', 'V-58165']
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
