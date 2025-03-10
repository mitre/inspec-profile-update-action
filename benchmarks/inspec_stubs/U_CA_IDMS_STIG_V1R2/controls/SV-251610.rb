control 'SV-251610' do
  title 'IDMS components that cannot be uninstalled must be disabled.'
  desc 'DBMSs must adhere to the principles of least functionality by providing only essential capabilities. At installation, all CA IDMS products are installed but can be disabled (i.e., forced to fail if invoked).'
  desc 'check', 'Log on to IDMS DC system and issue DCPROFIL. Scroll to the Product Intent Status screen. If any unused product has a status of "YES", this is a finding.'
  desc 'fix', 'Edit RHDCPINT source and remove or comment out products identified as unused. Reassemble, relink, and implement changes by either recycling any affected CV or by issuing the following commands in any affected CV: 

DCMT VARY NUCLEUS MODULE RHDCPINT NEW COPY 
DCMT VARY NUCLEUS RELOAD'
  impact 0.3
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55045r807695_chk'
  tag severity: 'low'
  tag gid: 'V-251610'
  tag rid: 'SV-251610r807697_rule'
  tag stig_id: 'IDMS-DB-000300'
  tag gtitle: 'SRG-APP-000141-DB-000092'
  tag fix_id: 'F-54999r807696_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
