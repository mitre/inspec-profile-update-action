control 'SV-93449' do
  title 'Tanium must be configured in a High-Availability (HA) setup to ensure minimal loss of data and minimal disruption to mission processes in the event of a system failure.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. Preserving application state information helps to facilitate application restart and return to the operational mode of the organization with less disruption to mission-essential processes.'
  desc 'check', 'If the system is not considered mission critical, this is Not Applicable.

Consult with the Tanium System Administrator to verify that Tanium is configured in a high-availability (HA) Active-Active setup.

If Tanium is not configured in a HA Active-Active setup, this is a finding.'
  desc 'fix', 'If the system is not considered mission critical, this is Not Applicable.

Work with the Tanium System Administrator to configure Tanium in a HA Active-Active setup based on the process outlined in the Tanium documentation found at https://docs.tanium.com/platform_install/platform_install/installing_an_ha_active_active_cluster.html.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78319r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78743'
  tag rid: 'SV-93449r1_rule'
  tag stig_id: 'TANS-SV-000054'
  tag gtitle: 'SRG-APP-000226'
  tag fix_id: 'F-85485r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
