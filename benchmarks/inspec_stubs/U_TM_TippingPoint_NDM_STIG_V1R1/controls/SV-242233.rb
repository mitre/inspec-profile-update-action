control 'SV-242233' do
  title 'The TippingPoint SMS must disable auto reconnect after disconnect.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Requiring authentication for auto reconnecting expired administrator sessions is a best practice that lowers the risk of DoS attacks.'
  desc 'check', '1. Log in to the SMS client. 
2. Select >> "Edit" >> "Preferences". Select "Security" Under "Client Preferences".
3. Verify the option for "Auto reconnect client to server after a disconnect occurs" is unchecked.

If the TippingPoint SMS does not disable auto reconnect after disconnect, this is a finding.'
  desc 'fix', '1. Log in to the SMS client. 
2. Select >> "Edit" >> "Preferences". Select "Security" Under "Client Preferences". Uncheck "Auto reconnect client to server after a disconnect occurs". 
3. Click OK.'
  impact 0.3
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45508r710704_chk'
  tag severity: 'low'
  tag gid: 'V-242233'
  tag rid: 'SV-242233r710706_rule'
  tag stig_id: 'TIPP-NM-000012'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-45466r710705_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
