control 'SV-237207' do
  title 'ColdFusion must limit the SQL commands available.'
  desc 'DoS is a condition when a resource is not available for legitimate users.  When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.  To reduce the possibility or effect of a DoS, the application server must employ defined security safeguards.  These safeguards will be determined by the placement of the application server and the type of applications being hosted within the application server framework.

Allowing hosted applications to execute SQL commands that create tables, change permissions on objects, create stored procedures, or drop objects allow an attacker to put the hosted application into a posture where it may not work correctly, display error messages that contains sensitive data that was not tested for during development, or cause an application to be unable to authenticate users.  Any of these situations puts the system into a situation where the user is denied service to the application.  Giving applications only those SQL commands needed to operate on data reduces this risk.'
  desc 'check', 'Within the Administrator Console, navigate to the "Data Sources" page under the "Data & Services" Settings menu.

If there are no data sources defined, this finding is not applicable.

Edit each data source and then view the advanced settings by pressing the "Show Advanced Settings" button.

If any of the data sources have CREATE, GRANT, DROP, REVOKE or ALTER checked, this is a finding.'
  desc 'fix', 'If there are no data sources defined, this finding is not applicable.

Navigate to the "Data Sources" page under the "Data & Services" Settings menu.  Edit each data source and view the advanced settings.  Uncheck the allow SQL of CREATE, GRANT, DROP, REVOKE and ALTER and select the "Submit" button.'
  impact 0.7
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40426r641714_chk'
  tag severity: 'high'
  tag gid: 'V-237207'
  tag rid: 'SV-237207r641716_rule'
  tag stig_id: 'CF11-05-000184'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag fix_id: 'F-40389r641715_fix'
  tag 'documentable'
  tag legacy: ['SV-76977', 'V-62487']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
