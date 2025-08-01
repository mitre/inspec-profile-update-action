control 'SV-218292' do
  title 'The /etc/passwd file must be owned by root.'
  desc 'The /etc/passwd file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.'
  desc 'check', 'Verify the /etc/passwd file is owned by root.

# ls -l /etc/passwd

If the file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the /etc/passwd file to root.

# chown root /etc/passwd'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19767r561665_chk'
  tag severity: 'medium'
  tag gid: 'V-218292'
  tag rid: 'SV-218292r603259_rule'
  tag stig_id: 'GEN001378'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19765r561666_fix'
  tag 'documentable'
  tag legacy: ['V-22332', 'SV-64549']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
