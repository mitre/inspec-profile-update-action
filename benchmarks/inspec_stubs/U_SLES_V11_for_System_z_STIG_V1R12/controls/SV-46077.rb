control 'SV-46077' do
  title 'The systems boot loader configuration files must be owned by root.'
  desc "The system's boot loader configuration files are critical to the integrity of the system and must be protected.  Unauthorized modification of these files resulting from improper ownership could compromise the system's boot loader configuration."
  desc 'check', 'Check the ownership of the file.
# ls -lLd /etc/zipl.conf

If the owner of the file is not root, this is a finding.'
  desc 'fix', 'Change the ownership of the file.
# chown root /etc/zipl.conf'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43336r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22586'
  tag rid: 'SV-46077r1_rule'
  tag stig_id: 'GEN008760'
  tag gtitle: 'GEN008760'
  tag fix_id: 'F-39423r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
