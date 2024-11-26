control 'SV-230766' do
  title 'The macOS system must be configured with the SSH daemon LoginGraceTime set to 30 or less.'
  desc 'SSH should be configured to log users out after a 15-minute interval of inactivity and to wait only 30 seconds before timing out logon attempts. Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session or an incomplete logon attempt will also free up resources committed by the managed network element.'
  desc 'check', 'If SSH is not being used, this is Not Applicable.

The SSH daemon "LoginGraceTime" must be set correctly. To check the amount of time that a user can log on through SSH, run the following command:

/usr/bin/grep ^LoginGraceTime /etc/ssh/sshd_config

If the value is not set to "30" or less, this is a finding.'
  desc 'fix', %q(To ensure that "LoginGraceTime" is configured correctly, run the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/.*LoginGraceTime.*/LoginGraceTime 30/' /etc/ssh/sshd_config)
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33711r808497_chk'
  tag severity: 'medium'
  tag gid: 'V-230766'
  tag rid: 'SV-230766r808498_rule'
  tag stig_id: 'APPL-11-000053'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-33684r607186_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
