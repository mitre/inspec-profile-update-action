control 'SV-76939' do
  title 'ColdFusion must have example gateway instances removed.'
  desc 'ColdFusion is installed with sample data services, gateway services, and collections.  These can be used in a development environment to learn how to use and develop applications and services, but these samples are not tested and patched for security issues.  Allowing them to be available on a production system provides a gateway to an attacker to the application server and to those systems connected to ColdFusion.  To alleviate this issue, sample code and services must be deleted.'
  desc 'check', 'Several sample services are installed with the ColdFusion server.  From the Administrator Console, go to the "Gateway Instances" page under the "Event Gateways" menu.

If the Gateway Instance SMS Menu App. exists, this is a finding.'
  desc 'fix', 'Remove the sample gateway instances by navigating to the "Gateway Instances" page under the "Event Gateways" menu.  Delete the Gateway Instance SMS Menu App.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63253r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62449'
  tag rid: 'SV-76939r1_rule'
  tag stig_id: 'CF11-03-000119'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-68369r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
