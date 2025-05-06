control 'SV-237187' do
  title 'ColdFusion must have example collections removed.'
  desc 'ColdFusion is installed with sample data services, gateway services, and collections.  These can be used in a development environment to learn how to use and develop applications and services, but these samples are not tested and patched for security issues.  Allowing them to be available on a production system provides a gateway to an attacker to the application server and to those systems connected to ColdFusion.  To alleviate this issue, sample code and services must be deleted.'
  desc 'check', 'Several sample services are installed with the ColdFusion server.  From the Administrator Console, go to the "ColdFusion Collections" page under the "Data & Services" menu.

If the bookclub collection exists, this is a finding.'
  desc 'fix', 'Remove the sample collections by navigating to the "ColdFusion Collections" page under the "Data & Services" menu.  Delete the bookclub collection.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40406r641654_chk'
  tag severity: 'medium'
  tag gid: 'V-237187'
  tag rid: 'SV-237187r641656_rule'
  tag stig_id: 'CF11-03-000118'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-40369r641655_fix'
  tag 'documentable'
  tag legacy: ['SV-76937', 'V-62447']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
