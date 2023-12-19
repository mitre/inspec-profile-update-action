control 'SV-26771' do
  title 'The SSH daemon must not accept environment variables from the client or must only accept those pertaining to locale.'
  desc "Environment variables can be used to change the behavior of remote sessions and should be limited.  Locale environment variables specify the language, character set, and other features modifying the operation of software to match the user's preferences."
  desc 'check', "Check the SSH daemon configuration for the AcceptEnv setting.
# grep -i AcceptEnv /etc/ssh/sshd_config | grep -v '^#' 
If any line is returned other than those permitting LOCALE or LC_* environment variables, this is a finding."
  desc 'fix', 'Edit the SSH daemon configuration and remove (or edit) the AcceptEnv setting(s) to only accept LOCALE or LC_* environment variables.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27778r1_chk'
  tag severity: 'low'
  tag gid: 'V-22477'
  tag rid: 'SV-26771r1_rule'
  tag stig_id: 'GEN005528'
  tag gtitle: 'GEN005528'
  tag fix_id: 'F-24020r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000221']
  tag nist: ['AC-4 (16)']
end
