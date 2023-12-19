control 'SV-234697' do
  title 'The version of Oracle JRE 8 running on the system must be the most current available.'
  desc 'Oracle JRE 8 is being continually updated by the vendor in order to address identified security vulnerabilities.  Running an older version of the JRE can introduce security vulnerabilities to the system.'
  desc 'check', 'Open a terminal window and type the command:
"java -version" sans quotes.

The return value should contain Java build information:

"Java (TM) SE Runtime Environment (build x.x.x.x)"

Cross-reference the build information on the system with the Oracle Java site to verify the version is supported by the vendor.

If the version of Oracle JRE 8 running on the system is unsupported, this is a finding.'
  desc 'fix', 'Test applications to ensure operational compatibility with new version of Java.

Install a supported version of Oracle JRE 8.'
  impact 0.7
  ref 'DPMS Target Oracle Java Runtime Environment v8 for Windows'
  tag check_id: 'C-37882r617345_chk'
  tag severity: 'high'
  tag gid: 'V-234697'
  tag rid: 'SV-234697r617446_rule'
  tag stig_id: 'JRE8-WN-000180'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-37847r617346_fix'
  tag 'documentable'
  tag legacy: ['SV-81457', 'V-66967']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
