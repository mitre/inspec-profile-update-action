control 'SV-81427' do
  title 'The version of Oracle JRE 8 running on the system must be the most current available.'
  desc 'Oracle JRE 8 is being continually updated by the vendor in order to address identified security vulnerabilities.  Running an older version of the JRE can introduce security vulnerabilities to the system.'
  desc 'check', 'Open a terminal window and type the command:
"java -version" sans quotes.

The return value should contain Java build information:

"Java (TM) SE Runtime Environment (build x.x.x.x)"

Cross reference the build information on the system with the Oracle Java site to identify the most recent build available.

If the version of Oracle JRE 8 running on the system is out of date, this is a finding.'
  desc 'fix', 'Test applications to ensure operational compatibility with new version of Java.

Install latest version of Oracle JRE 8.'
  impact 0.7
  ref 'DPMS Target JRE 8 (1.8)'
  tag check_id: 'C-67573r1_chk'
  tag severity: 'high'
  tag gid: 'V-66937'
  tag rid: 'SV-81427r1_rule'
  tag stig_id: 'JRE8-UX-000180'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-73037r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
