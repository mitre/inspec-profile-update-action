control 'SV-202085' do
  title 'The network device must be configured to provide a logout mechanism for administrator-initiated communication sessions.'
  desc 'If an administrator cannot explicitly end a device management session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session.'
  desc 'check', 'Review the network device configuration to determine if it is configured to enable a logout for administrator-initiated communication sessions.

If the network device is not configured to provide a logout mechanism for these sessions, this is a finding.'
  desc 'fix', 'Configure the network device to provide a logout capability for administrator-initiated communication sessions.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2211r381857_chk'
  tag severity: 'medium'
  tag gid: 'V-202085'
  tag rid: 'SV-202085r399526_rule'
  tag stig_id: 'SRG-APP-000296-NDM-000280'
  tag gtitle: 'SRG-APP-000296'
  tag fix_id: 'F-2212r381858_fix'
  tag 'documentable'
  tag legacy: ['SV-69443', 'V-55197']
  tag cci: ['CCI-002363']
  tag nist: ['AC-12 (1)']
end
