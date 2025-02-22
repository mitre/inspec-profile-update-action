control 'SV-227698' do
  title 'The system must be checked for extraneous device files at least weekly.'
  desc 'If an unauthorized device is allowed to exist on the system, there is the possibility the system may perform unauthorized operations.'
  desc 'check', 'Check the system for an automated job, or check with the SA, to determine if the system is checked for extraneous device files on a weekly basis. If no automated or manual process is in place, this is a finding.'
  desc 'fix', 'Establish a weekly automated or manual process to create a list of device files on the system and determine if any files have been added, moved, or deleted since the last list was generated.  

Generate a list of device files.
# find / -type b -o -type c > device-file-list'
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-36458r602977_chk'
  tag severity: 'low'
  tag gid: 'V-227698'
  tag rid: 'SV-227698r603266_rule'
  tag stig_id: 'GEN002260'
  tag gtitle: 'SRG-OS-000363'
  tag fix_id: 'F-36422r602978_fix'
  tag 'documentable'
  tag legacy: ['V-923', 'SV-923']
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end
