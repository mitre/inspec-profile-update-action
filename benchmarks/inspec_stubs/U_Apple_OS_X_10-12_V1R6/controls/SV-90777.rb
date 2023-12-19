control 'SV-90777' do
  title 'The OS X system must be configured with the SSH daemon ClientAliveInterval option set to 900 or less.'
  desc 'SSH should be configured to log users out after a 15-minute interval of inactivity and to wait only 30 seconds before timing out logon attempts. Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session or an incomplete logon attempt will also free up resources committed by the managed network element.'
  desc 'check', 'The SSH daemon "ClientAliveInterval" option must be set correctly. To check the idle timeout setting for SSH sessions, run the following:

/usr/bin/sudo /usr/bin/grep ^ClientAliveInterval /etc/ssh/sshd_config

If the setting is not "900" or less, this is a finding.'
  desc 'fix', %q(To ensure that "ClientAliveInterval" is set correctly, run the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/.*ClientAliveInterval.*/ClientAliveInterval 900/' /etc/ssh/sshd_config)
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75773r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76089'
  tag rid: 'SV-90777r1_rule'
  tag stig_id: 'AOSX-12-000720'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-82727r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
