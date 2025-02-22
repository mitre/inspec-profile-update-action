control 'SV-257164' do
  title 'The macOS system must be configured with the SSH daemon LoginGraceTime set to 30 or less.'
  desc 'SSH must be configured to log users out after a 15-minute interval of inactivity and to wait only 30 seconds before timing out logon attempts. Terminating an idle session within a short time reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session or an incomplete logon attempt will also free up resources committed by the managed network element.'
  desc 'check', 'If SSH is not being used, this is not applicable.

Verify the macOS system is configured with the SSH daemon "LoginGraceTime" option set to "30" or less with the following command:

/usr/bin/grep -r ^LoginGraceTime /etc/ssh/sshd_config*

If "LoginGraceTime" is not configured or has a value of "0", this is a finding.

If "LoginGraceTime" is not set to "30" or less, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', %q(Configure the macOS system to set the SSH daemon "LoginGraceTime" option to "30" with the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/.*LoginGraceTime.*/LoginGraceTime 30/' /etc/ssh/sshd_config)
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60849r905123_chk'
  tag severity: 'medium'
  tag gid: 'V-257164'
  tag rid: 'SV-257164r905125_rule'
  tag stig_id: 'APPL-13-000053'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-60790r905124_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
