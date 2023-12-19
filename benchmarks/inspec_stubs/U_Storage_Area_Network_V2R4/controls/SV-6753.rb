control 'SV-6753' do
  title 'The SAN must be configured to use bidirectional authentication.'
  desc 'Switch-to-switch management traffic does not have to be encrypted. Bidirectional authentication ensures that a rogue switch cannot be inserted and be auto configured to join the fabric.'
  desc 'check', 'Verify that all fabric switches are configured to bidirectional authentication.'
  desc 'fix', 'Configure the SAN fabric switches to use bidirectional authentication between switches.'
  impact 0.5
  ref 'DPMS Target SANS Storage Device'
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2487r2_chk'
  tag severity: 'medium'
  tag gid: 'V-6633'
  tag rid: 'SV-6753r2_rule'
  tag stig_id: 'SAN04.010.00'
  tag gtitle: 'Fabric Switches do not have bidirectional authentication'
  tag fix_id: 'F-6221r2_fix'
  tag 'documentable'
  tag potential_impacts: 'Failure to configure all components to use encryption could cause the SAN to degrade or fail.'
  tag responsibility: ['Information Assurance Officer', 'Switch Administrator']
end
