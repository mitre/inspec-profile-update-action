control 'SV-251375' do
  title 'Current and previous network element configurations must be stored in a secured location.'
  desc "If the network element's non-volatile memory is lost without a recent configuration stored in an offline location, it may take time to recover that segment of the network.  Users connected directly to the switch or router will be without service for a longer than acceptable time."
  desc 'check', 'At a minimum, a copy of the current and previous network element configurations must be saved.  Storage can take place on a classified network, OOB network, or offline.

If the current and previous network element configurations are not stored in a secured location, this is a finding.'
  desc 'fix', 'The network administrator will store the current and previous router and switch configurations in a secure location. Storage can take place on a classified network, OOB network, or offline.  Configurations can only be accessed by server or network admin.'
  impact 0.3
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54810r806078_chk'
  tag severity: 'low'
  tag gid: 'V-251375'
  tag rid: 'SV-251375r853654_rule'
  tag stig_id: 'NET1040'
  tag gtitle: 'NET1040'
  tag fix_id: 'F-54763r806079_fix'
  tag 'documentable'
  tag legacy: ['V-8061', 'SV-8547']
  tag cci: ['CCI-001785']
  tag nist: ['CM-8 (7)']
end
