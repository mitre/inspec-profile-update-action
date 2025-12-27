control 'SV-225139' do
  title 'The macOS system must be configured with the SSH daemon ClientAliveInterval option set to 900 or less.'
  desc 'SSH should be configured to log users out after a 15-minute interval of inactivity and to wait only 30 seconds before timing out logon attempts. Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session or an incomplete logon attempt will also free up resources committed by the managed network element.'
  desc 'check', 'The SSH daemon "ClientAliveInterval" option must be set correctly. To check the idle timeout setting for SSH sessions, run the following:

/usr/bin/sudo /usr/bin/grep ^ClientAliveInterval /etc/ssh/sshd_config

If the setting is not "900" or less, this is a finding.'
  desc 'fix', %q(To ensure that "ClientAliveInterval" is set correctly, run the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/.*ClientAliveInterval.*/ClientAliveInterval 900/' /etc/ssh/sshd_config)
  impact 0.5
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26838r467585_chk'
  tag severity: 'medium'
  tag gid: 'V-225139'
  tag rid: 'SV-225139r610901_rule'
  tag stig_id: 'AOSX-15-000051'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-26826r467586_fix'
  tag 'documentable'
  tag legacy: ['V-102695', 'SV-111657']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
