control 'SV-44657' do
  title 'The /etc/sysctl.conf file must have mode 0600 or less permissive.'
  desc "The sysctl.conf file specifies the values for kernel parameters to be set on boot.  These settings can affect the system's security."
  desc 'check', 'Check /etc/sysctl.conf permissions:

# ls -lL /etc/sysctl.conf

If /etc/sysctl.conf has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Use the chmod command to change the mode of the /etc/sysctl.conf file.
# chmod 0600 /etc/sysctl.conf'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42161r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4336'
  tag rid: 'SV-44657r1_rule'
  tag stig_id: 'GEN000000-LNX00520'
  tag gtitle: 'GEN000000-LNX00520'
  tag fix_id: 'F-38112r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
