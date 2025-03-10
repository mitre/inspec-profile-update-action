control 'SV-237173' do
  title 'ColdFusion must have example data sources removed.'
  desc 'ColdFusion is installed with sample data services, gateway services, and collections.  These can be used in a development environment to learn how to use and develop applications and services, but these samples are not tested and patched for security issues.  Allowing them to be available on a production system provides a gateway to an attacker to the application server and to those systems connected to ColdFusion.  To alleviate this issue, sample code and services must be deleted.'
  desc 'check', 'Several sample services are installed with the ColdFusion server.  From the Administrator Console, go to the "Data Sources" page under the "Data & Services" menu.

If the data sources cfartgallery, cfbookclub, cfcodeexplorer, or cfdocexamples exist, this is a finding.'
  desc 'fix', 'Remove the sample data sources by navigating to the "Data Sources" page under the "Data & Services" menu.  Delete the data sources cfartgallery, cfbookclub, cfcodeexplorer, and cfdocexamples.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40392r641612_chk'
  tag severity: 'medium'
  tag gid: 'V-237173'
  tag rid: 'SV-237173r641614_rule'
  tag stig_id: 'CF11-03-000103'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-40355r641613_fix'
  tag 'documentable'
  tag legacy: ['SV-76909', 'V-62419']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
