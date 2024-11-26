control 'SV-207625' do
  title 'The ESXi host SSH daemon must not accept environment variables from the client.'
  desc "Environment variables can be used to change the behavior of remote sessions and should be limited. Locale environment variables that specify the language, character set, and other features modifying the operation of software to match the user's preferences."
  desc 'check', 'From an SSH session connected to the ESXi host, or from the ESXi shell, run the following command:

# grep -i "^AcceptEnv" /etc/ssh/sshd_config

If there is no output or the output is not exactly "AcceptEnv", this is a finding.'
  desc 'fix', 'From an SSH session connected to the ESXi host, or from the ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

AcceptEnv'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7880r364274_chk'
  tag severity: 'medium'
  tag gid: 'V-207625'
  tag rid: 'SV-207625r388482_rule'
  tag stig_id: 'ESXI-65-000024'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7880r364275_fix'
  tag 'documentable'
  tag legacy: ['SV-104081', 'V-93995']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
