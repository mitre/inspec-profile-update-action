control 'SV-223760' do
  title 'IBM RACF must be installed and active on the system.'
  desc 'Enterprise environments make account management for operating systems challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other errors. IBM z/OS requires an external security manager to assure proper account management.'
  desc 'check', 'Refer to IEASYS00 member in SYS1.PARMLIB Concatenation. Determine proper IEFSSnxx member.

If RACF is defined in the SubSystem member, this is not a finding.'
  desc 'fix', 'Refer to the IBM Security Server RACF System Programmer Guide and the IBM Security Server RACF Security Administrator guide to properly implement RACF on the system.'
  impact 0.7
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25433r514968_chk'
  tag severity: 'high'
  tag gid: 'V-223760'
  tag rid: 'SV-223760r604139_rule'
  tag stig_id: 'RACF-OS-000040'
  tag gtitle: 'SRG-OS-000001-GPOS-00001'
  tag fix_id: 'F-25421r514969_fix'
  tag 'documentable'
  tag legacy: ['V-98227', 'SV-107331']
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
