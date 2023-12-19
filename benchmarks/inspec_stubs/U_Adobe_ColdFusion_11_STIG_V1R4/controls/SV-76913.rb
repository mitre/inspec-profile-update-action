control 'SV-76913' do
  title 'ColdFusion must have Remote Inspection disabled.'
  desc 'Application servers provide a myriad of differing processes, features, and functionalities. Some of these processes may be deemed to be unnecessary or too unsecure to run on a production DoD system.  Remote Inspection is used to debug mobile applications and may contain sensitive information.  This feature may be necessary as applications are built and tested, but once in a production environment, this setting is not necessary for daily operations and must be disabled.'
  desc 'check', 'Within the Administrator Console, navigate to the "Remote Inspection Settings" page under the "Debugging & Logging" menu.

If "Allow Remote Inspection" is checked, this is a finding.'
  desc 'fix', 'Navigate to the "Remote Inspection Settings" page under the "Debugging & Logging" menu.  Uncheck "Allow Remote Inspection" and select the "Submit Changes" button.'
  impact 0.7
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63227r1_chk'
  tag severity: 'high'
  tag gid: 'V-62423'
  tag rid: 'SV-76913r1_rule'
  tag stig_id: 'CF11-03-000105'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-68343r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
