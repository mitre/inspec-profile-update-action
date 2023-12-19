control 'SV-206810' do
  title 'The Voice Video Session Manager must automatically disable Voice Video endpoint user access after a 35 day period of account inactivity.'
  desc 'Attackers that are able to exploit an inactive account can potentially obtain and maintain undetected access to an application. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained. Voice video session managers must track periods of user inactivity and disable accounts after 35 days of inactivity. Such a process greatly reduces the risk that accounts will be misused, hijacked, or data compromised.

DoD has determined that 35 days is the appropriate time period of inactivity for Inactive accounts. Therefore, systems with a per user paradigm of management would apply.'
  desc 'check', 'Verify the Voice Video Session Manager automatically disables Voice Video endpoint user access after a 35 day period of account inactivity. This requirement refers to users rather than endpoints.

If the Voice Video Session Manager does not automatically disable Voice Video endpoint user access after a 35 day period of account inactivity, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager too automatically disable Voice Video endpoint user access after a 35 day period of account inactivity.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7065r364619_chk'
  tag severity: 'medium'
  tag gid: 'V-206810'
  tag rid: 'SV-206810r508661_rule'
  tag stig_id: 'SRG-NET-000004-VVSM-00010'
  tag gtitle: 'SRG-NET-000004'
  tag fix_id: 'F-7065r364620_fix'
  tag 'documentable'
  tag legacy: ['V-62049', 'SV-76539']
  tag cci: ['CCI-000017']
  tag nist: ['AC-2 (3) (d)']
end
