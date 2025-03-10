control 'SV-237197' do
  title 'ColdFusion must disable creation of unnamed applications.'
  desc 'ColdFusion allows applications to be named or unnamed.  The application name allows the developer to scope the application or define a logical application and allows for the separation of applications.  When an application is unnamed, the application scope corresponds to the ColdFusion JEE servlet context.  This also means that the application session corresponds directly to the session object of the JEE application server.  Having unnamed applications is only necessary when the ColdFusion pages must share application or session scope data with existing JSP pages and servlets.

Disabling the ability for unnamed applications allows the Administrator Console and all the other hosted applications to be isolated from each other.'
  desc 'check', 'Within the Administrator Console, navigate to the "Settings" page under the "Server Settings" menu.

If "Disable creation of unnamed applications" is unchecked, this is a finding.'
  desc 'fix', 'Navigate to the "Settings" page under the "Server Settings" menu.  Check "Disable creation of unnamed applications" and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40416r641684_chk'
  tag severity: 'medium'
  tag gid: 'V-237197'
  tag rid: 'SV-237197r641686_rule'
  tag stig_id: 'CF11-05-000163'
  tag gtitle: 'SRG-APP-000211-AS-000146'
  tag fix_id: 'F-40379r641685_fix'
  tag 'documentable'
  tag legacy: ['SV-76957', 'V-62467']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
