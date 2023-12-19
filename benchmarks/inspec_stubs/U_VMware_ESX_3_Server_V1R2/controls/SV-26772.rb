control 'SV-26772' do
  title 'The SSH client must not send environment variables to the server or must only send those pertaining to locale.'
  desc "Environment variables can be used to change the behavior of remote sessions and should be limited.  Locale environment variables specify the language, character set, and other features modifying the operation of software to match the user's preferences."
  desc 'check', "Check the SSH client configuration for the SendEnv setting.
# grep -i SendEnv /etc/ssh/ssh_config | grep -v '^#' 
If any line is returned other than those permitting LOCALE or LC_* environment variables, this is a finding."
  desc 'fix', 'Edit the SSH client configuration and remove (or edit) the SendEnv setting(s) to only accept LOCALE or LC_* environment variables.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27780r1_chk'
  tag severity: 'low'
  tag gid: 'V-22478'
  tag rid: 'SV-26772r1_rule'
  tag stig_id: 'GEN005529'
  tag gtitle: 'GEN005529'
  tag fix_id: 'F-24022r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000221']
  tag nist: ['AC-4 (16)']
end
