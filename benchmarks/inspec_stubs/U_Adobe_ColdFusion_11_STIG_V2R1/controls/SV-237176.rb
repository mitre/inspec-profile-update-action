control 'SV-237176' do
  title 'ColdFusion must protect internal cookies from being updated by hosted applications.'
  desc 'Application servers provide a myriad of differing processes, features, and functionalities. Some of these processes may be deemed to be unnecessary or too unsecure to run on a production DoD system.  Allowing developers to override global session cookie security settings is used to allow a hosted application to change the security posture of the application server.  This feature may be necessary as applications are built and tested, but once in a production environment, this functionality is not necessary for daily operations and must be disabled.'
  desc 'check', 'Within the Administrator Console, navigate to the "Memory Variables" page under the "Server Settings" menu.

If "Disable updating ColdFusion internal cookies using ColdFusion tags/functions." is unchecked, this is a finding.'
  desc 'fix', 'Navigate to the "Memory Variables" page under the "Server Settings" menu.   Check "Disable updating ColdFusion internal cookies using ColdFusion tags/functions." and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40395r641621_chk'
  tag severity: 'medium'
  tag gid: 'V-237176'
  tag rid: 'SV-237176r641623_rule'
  tag stig_id: 'CF11-03-000106'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-40358r641622_fix'
  tag 'documentable'
  tag legacy: ['SV-76915', 'V-62425']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
