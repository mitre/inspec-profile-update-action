control 'SV-28616' do
  title 'The organization must encrypt all network device configurations while stored offline.'
  desc "If a network device's non-volatile memory is lost without a recent configuration stored in an offline location, it may take time to recover that segment of the network.  Users connected directly to the switch or router will be without service for a longer than acceptable time. Encrypting the configuration stored offline protects the data at rest and provides additional security to prevent tampering and potentially cause a network outage if the configuration were to be put into service."
  desc 'check', 'Inspect the network element configurations that have been stored offline.

If the configurations are not encrypted, this is a finding.'
  desc 'fix', 'Encrypt all network device configurations stored offline.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-28855r4_chk'
  tag severity: 'medium'
  tag gid: 'V-23735'
  tag rid: 'SV-28616r3_rule'
  tag stig_id: 'NET1050'
  tag gtitle: 'Configurations are stored unencrypted.'
  tag fix_id: 'F-25887r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002345']
  tag nist: ['AC-23']
end
