control 'SV-214886' do
  title 'The macOS system must be configured with the SSH daemon ClientAliveInterval option set to 900 or less.'
  desc 'SSH should be configured to log users out after a 15-minute interval of inactivity and to wait only 30 seconds before timing out logon attempts. Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session or an incomplete logon attempt will also free up resources committed by the managed network element.'
  desc 'check', 'The SSH daemon "ClientAliveInterval" option must be set correctly. To check the idle timeout setting for SSH sessions, run the following:

/usr/bin/sudo /usr/bin/grep ^ClientAliveInterval /etc/ssh/sshd_config

If the setting is not "900" or less, this is a finding.'
  desc 'fix', %q(To ensure that "ClientAliveInterval" is set correctly, run the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/.*ClientAliveInterval.*/ClientAliveInterval 900/' /etc/ssh/sshd_config)
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16086r397230_chk'
  tag severity: 'medium'
  tag gid: 'V-214886'
  tag rid: 'SV-214886r609363_rule'
  tag stig_id: 'AOSX-13-000720'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-16084r397231_fix'
  tag 'documentable'
  tag legacy: ['SV-96365', 'V-81651']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
