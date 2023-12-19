control 'SV-80655' do
  title 'The HP FlexFabric Switch must protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation.'
  desc 'This requirement supports non-repudiation of actions taken by an administrator and is required in order to maintain the integrity of the configuration management process. All configuration changes to the HP FlexFabric Switch are logged, and administrators authenticate with two-factor authentication before gaining administrative access. Together, these processes will ensure the administrators can be held accountable for the configuration changes they implement.

To meet this requirement, the HP FlexFabric Switch must log administrator access and activity.'
  desc 'check', 'Check the HP FlexFabric log file to determine if logging is enabled:

[HP] display info-center

Information Center: Enabled

If the HP FlexFabric Switch does not have logging enabled, this is a finding.'
  desc 'fix', 'Enable informational center on the HP FlexFabric Switch:

[HP] info-center enable'
  impact 0.3
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66811r1_chk'
  tag severity: 'low'
  tag gid: 'V-66165'
  tag rid: 'SV-80655r1_rule'
  tag stig_id: 'HFFS-ND-000021'
  tag gtitle: 'SRG-APP-000080-NDM-000220'
  tag fix_id: 'F-72241r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
