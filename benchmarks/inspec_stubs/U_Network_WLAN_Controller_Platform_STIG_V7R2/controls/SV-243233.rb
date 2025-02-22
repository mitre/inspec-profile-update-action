control 'SV-243233' do
  title 'The WLAN inactive/idle session timeout must be set for 30 minutes or less.'
  desc 'A WLAN session that never terminates due to inactivity may allow an opening for an adversary to highjack the session to obtain access to the network.'
  desc 'check', '1. Review the relevant configuration screen of the WLAN controller or access point.
2. Verify the inactive/idle session timeout setting is set for 30 minutes or less. 

If the inactive/idle session timeout is not set to 30 minutes or less for the entire WLAN, or the WLAN does not have the capability to enable the session timeout feature, this is a finding.'
  desc 'fix', 'Set the WLAN inactive/idle session timeout to 30 minutes or less.'
  impact 0.5
  ref 'DPMS Target Network WLAN Controller Platform'
  tag check_id: 'C-46508r817088_chk'
  tag severity: 'medium'
  tag gid: 'V-243233'
  tag rid: 'SV-243233r817090_rule'
  tag stig_id: 'WLAN-NW-000300'
  tag gtitle: 'SRG-NET-000514'
  tag fix_id: 'F-46465r817089_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
