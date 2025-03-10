control 'SV-76905' do
  title 'ColdFusion must have Remote Adobe LiveCycle Data Management access disabled.'
  desc 'Application servers provide a myriad of differing processes, features, and functionalities. Some of these processes may be deemed to be unnecessary or too unsecure to run on a production DoD system.  Remote Adobe LiveCycle Data Management access allows LiveCycle Data Services ES to connect to the ColdFusion server through RMI and use CFCs to read and update data that supports a Flex application.  If this feature is not needed for hosted applications and is enabled, an attacker could use this feature to compromise the ColdFusion server.'
  desc 'check', 'Ask the administrator if LiveCycle Data Services ES are being used by any hosted applications.

If hosted applications are using the service, this is not a finding.

Within the Administrator Console, navigate to the "Flex Integration" page under the "Data & Services" menu.

If "Enable Remote Adobe LiveCycle Data Management access" is checked, this is a finding.'
  desc 'fix', 'Navigate to the "Flex Integration" page under the "Data & Services" menu.  Uncheck "Enable Remote Adobe Live Cycle Data Management access" and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63219r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62415'
  tag rid: 'SV-76905r1_rule'
  tag stig_id: 'CF11-03-000101'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-68335r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
