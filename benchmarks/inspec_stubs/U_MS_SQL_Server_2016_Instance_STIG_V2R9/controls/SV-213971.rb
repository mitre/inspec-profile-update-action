control 'SV-213971' do
  title 'SQL Server must maintain the authenticity of communications sessions by guarding against man-in-the-middle attacks that guess at Session ID values.'
  desc 'One class of man-in-the-middle, or session hijacking, attack involves the adversary guessing at valid session identifiers based on patterns in identifiers already known. 
 
The preferred technique for thwarting guesses at Session IDs is the generation of unique session identifiers using a FIPS 140-2 or FIPS 140-3 approved random number generator. 
 
However, it is recognized that available DBMS products do not all implement the preferred technique yet may have other protections against session hijacking. Therefore, other techniques are acceptable, provided they are demonstrated to be effective.'
  desc 'check', 'Verify that Windows is configured to require the use of FIPS compliant algorithms. 
 
Click Start >> Type "Local Security Policy" >> Press Enter >> Expand "Local Policies" >> Select "Security Options" >> Locate "System Cryptography:  Use FIPS compliant algorithms for encryption, hashing, and signing." 
 
If the Security Setting for this option is "Disabled", this is a finding.'
  desc 'fix', 'Configure Windows to require the use of FIPS compliant algorithms. 
 
Click Start >> Type "Local Security Policy" >> Press Enter >> Expand "Local Policies" >> Select "Security Options" >> Locate "System Cryptography:  Use FIPS compliant algorithms for encryption, hashing, and signing." >> Change the Setting option to "Enabled" >> Restart Windows'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15188r313696_chk'
  tag severity: 'medium'
  tag gid: 'V-213971'
  tag rid: 'SV-213971r879639_rule'
  tag stig_id: 'SQL6-D0-009200'
  tag gtitle: 'SRG-APP-000224-DB-000384'
  tag fix_id: 'F-15186r313697_fix'
  tag 'documentable'
  tag legacy: ['SV-93909', 'V-79203']
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
