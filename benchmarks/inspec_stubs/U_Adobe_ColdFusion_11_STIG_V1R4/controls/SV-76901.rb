control 'SV-76901' do
  title 'ColdFusion must have Event Gateway Services disabled.'
  desc 'Application servers provide a myriad of differing processes, features, and functionalities. Some of these processes may be deemed to be unnecessary or too unsecure to run on a production DoD system.  Event Gateway Services are used to pass events from external sources to ColdFusion components that are specified.  Since this gateway is accepting events from external sources, a listener must be present.  When enabled, along with the listener, memory, queues, and processes are available for gateway processes.  These resources can be used by an attacker and should be disabled if the feature is not being used for hosted applications.'
  desc 'check', 'Ask the administrator if Event Gateway services are being used by any hosted applications.

If hosted applications are using the service, this is not a finding.

Within the Administrator Console, navigate to the "Settings" page under the "Event Gateways" menu.

If "Enable ColdFusion Event Gateway Services" is checked, this is a finding.'
  desc 'fix', 'Navigate to the "Settings" page under the "Event Gateway" menu.  Uncheck "Enable ColdFusion Event Gateway Services" and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63215r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62411'
  tag rid: 'SV-76901r1_rule'
  tag stig_id: 'CF11-03-000099'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-68331r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
