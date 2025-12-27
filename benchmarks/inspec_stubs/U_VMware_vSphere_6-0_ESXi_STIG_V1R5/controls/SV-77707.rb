control 'SV-77707' do
  title 'The SSH daemon must not accept environment variables from the client.'
  desc "Environment variables can be used to change the behavior of remote sessions and should be limited. Locate environment variables that specify the language, character set, and other features modifying the operation of software to match the user's preferences."
  desc 'check', 'To verify the AcceptEnv setting, run the following command: 

# grep -i "^AcceptEnv" /etc/ssh/sshd_config

If there is no output or the output is not exactly "AcceptEnv", this is a finding.'
  desc 'fix', 'To set the AcceptEnv setting, add or correct the following line in "/etc/ssh/sshd_config":

AcceptEnv'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63951r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63217'
  tag rid: 'SV-77707r1_rule'
  tag stig_id: 'ESXI-06-000024'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69135r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
