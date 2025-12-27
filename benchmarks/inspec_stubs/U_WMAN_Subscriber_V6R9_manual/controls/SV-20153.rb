control 'SV-20153' do
  title 'When a WMAN system is implemented, the network enclave must enforce strong authentication from user to DoD enclave (wired network).  For “User to Enclave” authentication, the enclave must enforce network authentication requirements found in USCYBERCOM CTO 07-15Rev1 (or subsequent updates) (e.g. CAC authentication).

Note:  User authentication to the enclave must be a separate process from authentication to the WMAN system.  If the WMAN vendor implements CAC authentication for the User or WMAN subscriber device to WMAN network, the user may only need to enter their PIN once to authenticate to both the WMAN system and the enclave.'
  desc 'Without strong user authentication to the network a hacker may be able to gain access.'
  desc 'check', 'Interview the IAO and network system administrator to determine if the site’s network is configured to require CAC authentication before a WMAN user is connected to the network.  If possible, have a user set up a WMAN connection and verify the user is required to CAC authenticate before they gain access to the local network.  Mark as a finding if a WMAN user is not required to CAC authenticate to the network prior to gaining network access.'
  desc 'fix', 'Comply with policy.'
  impact 0.5
  ref 'DPMS Target Wireless Client'
  tag check_id: 'C-22268r1_chk'
  tag severity: 'medium'
  tag gid: 'V-18602'
  tag rid: 'SV-20153r1_rule'
  tag stig_id: 'WIR0320'
  tag gtitle: 'WMAN authentication - User to Enclave'
  tag fix_id: 'F-14436r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECWN-1'
end
