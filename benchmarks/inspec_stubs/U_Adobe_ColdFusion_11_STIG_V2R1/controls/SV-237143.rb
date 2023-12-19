control 'SV-237143' do
  title 'ColdFusion must control remote access to the Administrator Console.'
  desc 'Application servers provide remote access capability and must be able to enforce remote access policy requirements or work in conjunction with enterprise tools designed to enforce policy requirements.  Automated monitoring and control of remote access sessions allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by logging connection activities of remote users.

By default, localhost and all IP addresses can access the Administrator Console.  Depending on the authentication method (i.e. single password, separate user name and password per user, or no authentication needed), any user from any network is capable of accessing the console and making changes to the server configuration relying only on the authentication method configured for the installation.  By limiting the IP addresses that can connect, the administration console can be hosted to a management network and only accessed via that network, further reducing the exposure of the Administrator Console.'
  desc 'check', 'Within the Administrator Console, navigate to the "Allowed IP Addresses" page under the "Security" menu.

If the list of allowed IP addresses for accessing the ColdFusion Administrator is blank, is set to "*.*.*.*" or contains IP addresses/subnets that should not have access, this is a finding.'
  desc 'fix', 'Navigate to the "Allowed IP Addresses" page under the "Security" menu.  Set the list of allowed IP addresses for accessing ColdFusion Administrator to only those IP addresses or subnets that should be capable of reaching the Administrator Console.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40362r641522_chk'
  tag severity: 'medium'
  tag gid: 'V-237143'
  tag rid: 'SV-237143r641524_rule'
  tag stig_id: 'CF11-01-000016'
  tag gtitle: 'SRG-APP-000315-AS-000094'
  tag fix_id: 'F-40325r641523_fix'
  tag 'documentable'
  tag legacy: ['SV-76849', 'V-62359']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
