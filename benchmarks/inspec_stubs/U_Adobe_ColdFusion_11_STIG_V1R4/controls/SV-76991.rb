control 'SV-76991' do
  title 'ColdFusion must set a timeout for logins.'
  desc 'DoS is a condition when a resource is not available for legitimate users.  When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.  To reduce the possibility or effect of a DoS, the application server must employ defined security safeguards.  These safeguards will be determined by the placement of the application server and the type of applications being hosted within the application server framework.

The "Login Timeout" setting is used to terminate login attempts on data sources that have not been fulfilled in the set time.  This parameter prevents unusually long logins from occupying server resources and impairing performance.  This value should be set to 5 or less and be less than or equal to the value for "Timeout Requests after" setting.'
  desc 'check', 'Within the Administrator Console, navigate to the "Data Sources" page under the "Data & Services" menu.

If there are no data sources defined, this finding is not applicable.

For each Data Source, view the "Login Timeout (sec)" setting within the Advanced Settings for the data source by editing the data source and then pressing the "Show Advanced Settings" button.

If there are any data sources with a "Login Timeout (sec)" set higher than 5, this is a finding.'
  desc 'fix', 'Navigate to the  "Data Sources" page under the "Data & Services" menu. Edit each data source and set the "Login Timeout (sec)" to 5 or less within the advanced settings for the data source.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63305r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62501'
  tag rid: 'SV-76991r1_rule'
  tag stig_id: 'CF11-05-000191'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag fix_id: 'F-68421r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
