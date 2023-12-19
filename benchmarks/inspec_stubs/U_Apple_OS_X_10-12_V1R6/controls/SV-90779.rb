control 'SV-90779' do
  title 'The OS X system must be configured with the SSH daemon ClientAliveCountMax option set to 0.'
  desc 'SSH should be configured to log users out after a 15-minute interval of inactivity and to wait only 30 seconds before timing out logon attempts. Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session or an incomplete logon attempt will also free up resources committed by the managed network element.'
  desc 'check', 'The SSH daemon "ClientAliveCountMax" option must be set correctly. To verify the SSH idle timeout will occur when the "ClientAliveCountMax" is set, run the following command:

/usr/bin/sudo /usr/bin/grep ^ClientAliveCountMax /etc/ssh/sshd_config

If the setting is not "ClientAliveCountMax 0", this is a finding.'
  desc 'fix', %q(To ensure that the SSH idle timeout occurs precisely when the "ClientAliveCountMax" is set, run the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/.*ClientAliveCountMax.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config)
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75775r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76091'
  tag rid: 'SV-90779r1_rule'
  tag stig_id: 'AOSX-12-000721'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-82729r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
