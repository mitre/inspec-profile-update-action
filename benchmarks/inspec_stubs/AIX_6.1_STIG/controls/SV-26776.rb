control 'SV-26776' do
  title 'The SSH daemon must limit connections to a single session.'
  desc 'The SSH protocol has the ability to provide multiple sessions over a single connection without reauthentication.  A compromised client could use this feature to establish additional sessions to a system without consent or knowledge of the user.

Alternate per-connection session limits may be documented if needed for a valid mission requirement.  Greater limits are expected to be necessary in situations where TCP or X11 forwarding are used.'
  desc 'check', "Check the SSH daemon configuration for the MaxSessions setting.
# grep -i MaxSessions /etc/ssh/sshd_config | grep -v '^#' 
If the setting is not present, or not set to 1, this is a finding."
  desc 'fix', 'Edit the SSH daemon configuration and add or edit the MaxSessions setting value to 1.'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-27784r1_chk'
  tag severity: 'low'
  tag gid: 'V-22482'
  tag rid: 'SV-26776r1_rule'
  tag stig_id: 'GEN005533'
  tag gtitle: 'GEN005533'
  tag fix_id: 'F-24026r1_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
