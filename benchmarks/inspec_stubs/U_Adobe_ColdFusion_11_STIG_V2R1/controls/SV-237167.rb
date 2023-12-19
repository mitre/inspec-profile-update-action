control 'SV-237167' do
  title 'ColdFusion must disable Flash Remoting support.'
  desc 'Application servers provide a myriad of differing processes, features and functionalities. Some of these processes may be deemed to be unnecessary or too unsecure to run on a production DoD system.  Flash Remoting allows a Flash client to connect to the ColdFusion server and invoke ColdFusion Components (CFCs).  Allowing this service to be enabled when not needed by hosted applications and when ColdFusion server monitoring is not being used provides an avenue for an attacker to gain access to the server.'
  desc 'check', 'Ask the administrator if ColdFusion server monitoring is being used or if flex remoting is being used by any hosted applications.

If ColdFusion server monitoring is being used or hosted applications are using flash remoting, this is not a finding.

Within the Administrator Console, navigate to the "Flex Integration" page under the "Data & Services" menu.

If the "Enable Flash Remoting" option is checked, this is a finding.'
  desc 'fix', 'Navigate to the "Flex Integration" page under the "Data & Services" menu.  Uncheck the "Enable Flash Remoting" option and select the "Submit Changes" button.'
  impact 0.7
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40386r641594_chk'
  tag severity: 'high'
  tag gid: 'V-237167'
  tag rid: 'SV-237167r641596_rule'
  tag stig_id: 'CF11-03-000097'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-40349r641595_fix'
  tag 'documentable'
  tag legacy: ['SV-76897', 'V-62407']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
