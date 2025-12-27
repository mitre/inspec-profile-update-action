control 'SV-230764' do
  title 'The macOS system must be configured with the SSH daemon ClientAliveInterval option set to 900 or less.'
  desc 'SSH should be configured to log users out after a 15-minute interval of inactivity and to wait only 30 seconds before timing out logon attempts. Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session or an incomplete logon attempt will also free up resources committed by the managed network element.'
  desc 'check', 'If SSH is not being used, this is Not Applicable.

The SSH daemon "ClientAliveInterval" option must be set correctly. To check the idle timeout setting for SSH sessions, run the following:

/usr/bin/grep ^ClientAliveInterval /etc/ssh/sshd_config

If the setting is not "900" or less, this is a finding.'
  desc 'fix', %q(To ensure that "ClientAliveInterval" is set correctly, run the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/.*ClientAliveInterval.*/ClientAliveInterval 900/' /etc/ssh/sshd_config)
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33709r808493_chk'
  tag severity: 'medium'
  tag gid: 'V-230764'
  tag rid: 'SV-230764r808494_rule'
  tag stig_id: 'APPL-11-000051'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-33682r607180_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
