control 'SV-209547' do
  title 'The macOS system must be configured with the SSH daemon ClientAliveCountMax option set to 0.'
  desc 'SSH should be configured with an Active Client Alive Maximum Count of 0. Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session or an incomplete logon attempt will also free up resources committed by the managed network element.'
  desc 'check', 'The SSH daemon "ClientAliveCountMax" option must be set correctly. To verify the SSH idle timeout will occur when the "ClientAliveCountMax" is set, run the following command:

/usr/bin/sudo /usr/bin/grep ^ClientAliveCountMax /etc/ssh/sshd_config

If the setting is not "ClientAliveCountMax 0", this is a finding.'
  desc 'fix', %q(To ensure that the SSH idle timeout occurs precisely when the "ClientAliveCountMax" is set, run the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/.*ClientAliveCountMax.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config)
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9798r282123_chk'
  tag severity: 'medium'
  tag gid: 'V-209547'
  tag rid: 'SV-209547r610285_rule'
  tag stig_id: 'AOSX-14-000052'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-9798r282124_fix'
  tag 'documentable'
  tag legacy: ['SV-104967', 'V-95829']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
