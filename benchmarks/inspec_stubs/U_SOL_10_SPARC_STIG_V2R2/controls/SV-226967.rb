control 'SV-226967' do
  title 'X Window System connections that are not required must be disabled.'
  desc "If unauthorized clients are permitted access to the X server, a user's X session may be compromised."
  desc 'check', 'Determine if the X Window system is running.

Procedure:
# ps -ef |grep X

Ask the SA if the X Window system is an operational requirement. If it is not, this is a finding.'
  desc 'fix', 'Disable the X Windows server on the system.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29129r485231_chk'
  tag severity: 'medium'
  tag gid: 'V-226967'
  tag rid: 'SV-226967r603265_rule'
  tag stig_id: 'GEN005260'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-29117r485232_fix'
  tag 'documentable'
  tag legacy: ['V-12018', 'SV-12519']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
