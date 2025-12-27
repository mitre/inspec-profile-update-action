control 'SV-38418' do
  title 'User start-up files must not execute world-writable programs.'
  desc 'If start-up files execute world-writable programs, especially in unprotected directories, they could be maliciously modified to become Trojans destroying user files or otherwise compromise the system at the user level or higher. If the system is compromised at the user level, it is much easier to eventually compromise the system at the root and network level.'
  desc 'check', 'Check local initialization files for any executed world-writable programs or scripts.

Procedure:
# more /<usershomedirectory>/.* 
# ls -alL <program or script>

If any local initialization file executes a world-writable program or script, this is a finding.'
  desc 'fix', 'Remove the world-writable permission of files referenced by local initialization scripts, or remove the references to these files in the local initialization scripts.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36370r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4087'
  tag rid: 'SV-38418r1_rule'
  tag stig_id: 'GEN001940'
  tag gtitle: 'GEN001940'
  tag fix_id: 'F-31707r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCSW-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
