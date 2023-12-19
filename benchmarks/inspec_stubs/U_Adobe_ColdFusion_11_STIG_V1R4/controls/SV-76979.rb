control 'SV-76979' do
  title 'ColdFusion must set a query timeout for Data Sources.'
  desc 'DoS is a condition when a resource is not available for legitimate users.  When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.  To reduce the possibility or effect of a DoS, the application server must employ defined security safeguards.  These safeguards will be determined by the placement of the application server and the type of applications being hosted within the application server framework.

One way to cause a DoS for ColdFusion is to exhaust resources by executing a query that will never return or timeout.  By having no timeout set, this type of DoS would be available to an attacker.  By setting a value greater than 0 (0 means no timeout), the query would be stopped and the resources released.'
  desc 'check', 'Within the Administrator Console, navigate to the "Data Sources" page under the "Data & Services" Settings menu.

If there are no data sources defined, this finding is not applicable.

Edit each data source and then view the advanced settings by pressing the "Show Advanced Settings" button.  Check to see if the data source has the capability to specify a query timeout.  If available, this parameter must not be 0 (No Timeout).

If a data source does not have this setting, then this is not a finding for this data source. 

If any of the data sources have a query timeout set to 0, this is a finding.'
  desc 'fix', 'If there are no data sources defined, this finding is not applicable.

Navigate to the "Data Sources" page under the "Data & Services" Settings menu.  Edit each data source and view the advanced settings.  If the data source has a query timeout parameter, set the timeout parameter to a value greater than 0 and select the "Submit" button.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63293r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62489'
  tag rid: 'SV-76979r1_rule'
  tag stig_id: 'CF11-05-000185'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag fix_id: 'F-68409r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
