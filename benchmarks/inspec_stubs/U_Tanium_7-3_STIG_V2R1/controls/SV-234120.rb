control 'SV-234120' do
  title 'The Tanium application must be configured in a High-Availability (HA) setup to ensure minimal loss of data and minimal disruption to mission processes in the event of a system failure.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. Preserving application state information helps to facilitate application restart and return to the operational mode of the organization with less disruption to mission-essential processes.'
  desc 'check', 'If the system is not considered mission critical, this is Not Applicable.

Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Packages".

Browse to the package called "Distribute Tanium Standard Utilities".

Select it.

Press "Status".

Observe the text underneath a package file indicating the file cache status.

If the cache status represents only one Tanium Server, this is a finding.'
  desc 'fix', 'If the system is not considered mission critical, this is Not Applicable.

Work with the Tanium System Administrator to configure Tanium in a HA Active-Active setup based on the process outlined in the Tanium documentation found at:

https://docs.tanium.com/platform_install/platform_install/installing_an_ha_active_active_cluster.html.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37305r610860_chk'
  tag severity: 'medium'
  tag gid: 'V-234120'
  tag rid: 'SV-234120r612749_rule'
  tag stig_id: 'TANS-SV-000054'
  tag gtitle: 'SRG-APP-000226'
  tag fix_id: 'F-37270r610861_fix'
  tag 'documentable'
  tag legacy: ['SV-102313', 'V-92211']
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
