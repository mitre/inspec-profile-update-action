control 'SV-26086' do
  title 'All local file systems must employ journaling or another mechanism ensuring file system consistency.'
  desc 'File system journaling, or logging, can allow reconstruction of file system data after a system crash, thus preserving the integrity of data that may have otherwise been lost.  Journaling file systems typically do not require consistency checks upon booting after a crash, which can improve system availability.  Some file systems employ other mechanisms to ensure consistency which also satisfy this requirement.'
  desc 'check', 'Determine if the local file systems employ journaling or another mechanism ensuring file system consistency.  If any do not, this is a finding.'
  desc 'fix', 'Convert local file systems to use journaling or another mechanism ensuring file system consistency.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29259r1_chk'
  tag severity: 'low'
  tag gid: 'V-22422'
  tag rid: 'SV-26086r1_rule'
  tag stig_id: 'GEN003650'
  tag gtitle: 'GEN003650'
  tag fix_id: 'F-23880r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000553']
  tag nist: ['CP-10 (2)']
end
