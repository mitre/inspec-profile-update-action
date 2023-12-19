control 'SV-80715' do
  title 'Network devices must provide a logoff capability for administrator-initiated communication sessions.'
  desc 'If an administrator cannot explicitly end a device management session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session.'
  desc 'check', 'Review the HP FlexFabric Switch configuration to determine if it provides a logoff capability for administrator-initiated communication sessions.

[HP] display users

  Idx  Line     Idle       Time              Pid     Type
+ 177  VTY 0    00:00:00   May 29 15:45:11   1011    SSH

Following are more details.
VTY 0   :
        User name: admin@system
        Location: 16.117.204.17
 +    : Current operation user.
 F    : Current operation user works in async mode.

If the HP FlexFabric Switch does not provide a logoff capability for these sessions, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to provide a logoff capability for administrator-initiated communication sessions.

[HP] Ctrl + z
<HP> quit'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66871r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66225'
  tag rid: 'SV-80715r1_rule'
  tag stig_id: 'HFFS-ND-000082'
  tag gtitle: 'SRG-APP-000296-NDM-000280'
  tag fix_id: 'F-72301r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002363']
  tag nist: ['AC-12 (1)']
end
