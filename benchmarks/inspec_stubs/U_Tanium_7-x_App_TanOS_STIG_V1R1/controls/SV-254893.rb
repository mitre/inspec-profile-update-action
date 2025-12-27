control 'SV-254893' do
  title 'Tanium Comply must be configured to receive SCAP content only from trusted sources.'
  desc 'NIST-validated SCAP XML documents are provided from several possible sources such as DISA, NIST, and the other nongovernment entities. These documents are used as the basis of compliance definitions leveraged to automate compliance auditing of systems. These documents are updated on different frequencies and must be manually downloaded on regular intervals and imported to be current. Nonapproved SCAP definitions lead to a false sense of security when evaluating an enterprise environment.'
  desc 'check', '1. Using a web browser on a system, that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Modules" on the top banner of the console.

3. Click "Comply".

4. Click the menu on the left side of the interface and then click "Compliance" under "Standards".

Verify all imported compliance benchmarks are from a documented trusted source.

If any compliance benchmark is found that does not come from a documented trusted source, this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Modules" on the top banner of the console.

3. Click "Comply".

4. Click the menu on the left side of the interface and then click "Compliance" under "Standards".

5. Delete any compliance benchmarks that come from nontrusted sources.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58506r867577_chk'
  tag severity: 'medium'
  tag gid: 'V-254893'
  tag rid: 'SV-254893r867579_rule'
  tag stig_id: 'TANS-AP-000160'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-58450r867578_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
