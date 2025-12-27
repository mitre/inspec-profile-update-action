control 'SV-76959' do
  title 'ColdFusion must not allow application variables to be added to Servlet Context.'
  desc 'ColdFusion allows applications to add application variables to the Servlet Context.  This allows an application to add data or change configuration data for all hosted applications.  By sharing data across applications, the applications are no longer isolated with one application affecting other applications.  By disabling this capability, the hosted applications, including the Administrator Console, are isolated.'
  desc 'check', 'Within the Administrator Console, navigate to the "Settings" page under the "Server Settings" menu.

If "Allow adding application variables to Servlet Context" is checked, this is a finding.'
  desc 'fix', 'Navigate to the "Settings" page under the "Server Settings" menu.  Uncheck "Allow adding application variables to Servlet Context" and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63273r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62469'
  tag rid: 'SV-76959r1_rule'
  tag stig_id: 'CF11-05-000164'
  tag gtitle: 'SRG-APP-000211-AS-000146'
  tag fix_id: 'F-68389r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
