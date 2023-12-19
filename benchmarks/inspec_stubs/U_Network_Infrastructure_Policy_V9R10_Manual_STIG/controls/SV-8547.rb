control 'SV-8547' do
  title 'Current and previous network element configurations must be stored in a secured location.'
  desc "If the network element's non-volatile memory is lost without a recent configuration stored in an offline location, it may take time to recover that segment of the network.  Users connected directly to the switch or router will be without service for a longer than acceptable time."
  desc 'check', 'At a minimum, a copy of the current and previous network element configurations must be saved.  Storage can take place on a classified network, OOB network, or offline.

If the current and previous network element configurations are not stored in a secured location, this is a finding.'
  desc 'fix', 'The network administrator will store the current and previous router and switch configurations in a secure location. Storage can take place on a classified network, OOB network, or offline.  Configurations can only be accessed by server or network admin.'
  impact 0.3
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-7442r2_chk'
  tag severity: 'low'
  tag gid: 'V-8061'
  tag rid: 'SV-8547r2_rule'
  tag stig_id: 'NET1040'
  tag gtitle: 'Configurations are not stored in a secure location'
  tag fix_id: 'F-7636r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001785']
  tag nist: ['CM-8 (7)']
end
