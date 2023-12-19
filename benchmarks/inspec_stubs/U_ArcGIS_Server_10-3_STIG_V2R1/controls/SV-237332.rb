control 'SV-237332' do
  title 'The ArcGIS Server must be configured such that emergency accounts are never automatically removed or disabled.'
  desc 'Emergency accounts are administrator accounts which are established in response to crisis situations where the need for rapid account activation is required. Therefore, emergency account activation may bypass normal account authorization processes. If these accounts are automatically disabled, system maintenance during emergencies may not be possible, thus adversely affecting system availability. 

Emergency accounts are different from infrequently used accounts (i.e., local logon accounts used by system administrators when network or normal logon/access is not available). Infrequently used accounts also remain available and are not subject to automatic termination dates. However, an emergency account is normally a different account which is created for use by vendors or system maintainers.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'Review the ArcGIS Server configuration to ensure emergency accounts are never automatically removed or disabled. Substitute the target environment’s values for [bracketed] variables. 

Log on to the ArcGIS Server Administrator Directory ([https://[server.domain.com])/arcgis/admin) (log on when promoted) with an account that has administrative access.

Navigate to security >> psa. Verify that the Primary Site Administrator account has not been disabled.

If the "Primary Site Administrator" account has been disabled, this is a finding.'
  desc 'fix', 'Configure the ArcGIS Server to ensure emergency accounts are never automatically removed or disabled. Substitute the target environment’s values for [bracketed] variables. 

Log on to the ArcGIS Server Administrator Directory ([https://[server.domain.com])/arcgis/admin) with an account that has administrative access.

Navigate to security >> psa >> enable to enable the "Primary Site Administrator" account.'
  impact 0.5
  ref 'DPMS Target ArcGIS for Server 10-3'
  tag check_id: 'C-40551r642813_chk'
  tag severity: 'medium'
  tag gid: 'V-237332'
  tag rid: 'SV-237332r879644_rule'
  tag stig_id: 'AGIS-00-000104'
  tag gtitle: 'SRG-APP-000234'
  tag fix_id: 'F-40514r642814_fix'
  tag 'documentable'
  tag legacy: ['SV-79975', 'V-65485']
  tag cci: ['CCI-001682']
  tag nist: ['AC-2 (2)']
end
