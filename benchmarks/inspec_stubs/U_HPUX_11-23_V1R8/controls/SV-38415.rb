control 'SV-38415' do
  title 'The system boot loader must protect passwords using an MD5 or stronger cryptographic hash.'
  desc 'If system boot loader passwords are compromised, users with console access to the system may be able to alter the system boot configuration or boot the system into single user or maintenance mode, which could result in Denial of Service or unauthorized privileged access to the system.'
  desc 'check', 'Check Content:  
When booting HP-UX, in order to access the Initial System Loader (ISL), the Boot Console Handler (BCH) must be intentionally interrupted. Once interrupted, the console will prompt for ISL access and halt briefly for a reply. If no reply is received, the system will time out and eventually execute the AUTO file. Neither the BCH nor the ISL are password protectable (by vendor design).

This check is not applicable (NA) to HP-UX.'
  desc 'fix', 'Not applicable (NA) to HP-UX.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36800r1_chk'
  tag severity: 'medium'
  tag gid: 'V-24624'
  tag rid: 'SV-38415r1_rule'
  tag stig_id: 'GEN008710'
  tag gtitle: 'GEN008710'
  tag fix_id: 'F-32177r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-2, IAIA-1'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
