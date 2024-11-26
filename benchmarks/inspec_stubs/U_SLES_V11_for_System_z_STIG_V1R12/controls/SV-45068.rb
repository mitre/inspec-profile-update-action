control 'SV-45068' do
  title 'Run control scripts must not execute world-writable programs or scripts.'
  desc 'World-writable files could be modified accidentally or maliciously to compromise system integrity.'
  desc 'check', 'Check the permissions on the files or scripts executed from system startup scripts to see if they are world-writable.

Procedure:
# more <startup script>
# ls -lL <script or executable referenced by startup script>

Alternatively, obtain a list of all world-writable files on the system and check system startup scripts to determine if any are referenced.

Procedure:
# find / -perm -0002 -type f | grep –v ‘^/proc’ > wwlist
If any system startup script executes any file or script that is world-writable, this is a finding.'
  desc 'fix', 'Remove the world-writable permission from programs or scripts executed by run control scripts.

Procedure:
# chmod o-w <program or script executed from run control script>'
  impact 0.7
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42440r1_chk'
  tag severity: 'high'
  tag gid: 'V-910'
  tag rid: 'SV-45068r1_rule'
  tag stig_id: 'GEN001640'
  tag gtitle: 'GEN001640'
  tag fix_id: 'F-38475r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
