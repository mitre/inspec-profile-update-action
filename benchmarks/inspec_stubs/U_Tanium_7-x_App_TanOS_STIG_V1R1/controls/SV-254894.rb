control 'SV-254894' do
  title 'Tanium Comply must be configured to receive OVAL feeds only from trusted sources.'
  desc 'OVAL XML documents are provided from several possible sources such as the CIS open source repository, or any number of vendor/third party paid repositories. These documents are used to automate the passive validation of vulnerabilities on systems and therefore require a reasonable level of confidence in their origin. Nonapproved OVAL definitions lead to a false sense of security when evaluating an enterprise environment.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Modules" on the top navigation banner.

3. Click "Comply".

4. Expand the left menu. 

5. Under "Standards," click "Vulnerability".

6. Verify all imported vulnerability sources are from a documented trusted source.

If any vulnerability sources are found that do not come from a documented trusted source, this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Modules" on the top navigation banner.

3. Click "Comply".

4. Expand the left menu. 

5. Under "Standards," click "Vulnerability".

6. Delete any vulnerability sources configured to nontrusted sources, or reconfigure to point to trusted sources.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58507r867580_chk'
  tag severity: 'medium'
  tag gid: 'V-254894'
  tag rid: 'SV-254894r867582_rule'
  tag stig_id: 'TANS-AP-000165'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-58451r867581_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
