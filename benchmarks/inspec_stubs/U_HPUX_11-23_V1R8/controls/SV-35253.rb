control 'SV-35253' do
  title 'The system must be configured to only boot from the system boot device.'
  desc 'The ability to boot from removable media is the same as being able to boot into single user or maintenance mode without a password.  This ability could allow a malicious user to boot the system and perform changes possibly compromising or damaging the system.  It could also allow the system to be used for malicious purposes by a malicious anonymous user.'
  desc 'check', 'HP-UX 11-v2 may be booted from the following system startup media (must have been previously configured by root):
•	Hard drives
•	CD/DVD drives (for installation)
•	Tape drives (for installation)
•	USB device  (configured with the Ignite boot content)

Determine if the system is configured to boot from devices other than the system startup media. Verification should (optimally) be performed during IPL/ISL boot. In lieu of rebooting the system, ask the SA if the system is configured to boot from devices other than system startup media.  If so, this is a finding.'
  desc 'fix', 'Configure the system to only boot from system startup media.'
  impact 0.7
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-35114r1_chk'
  tag severity: 'high'
  tag gid: 'V-1013'
  tag rid: 'SV-35253r1_rule'
  tag stig_id: 'GEN008600'
  tag gtitle: 'GEN008600'
  tag fix_id: 'F-1167r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
