control 'SV-230764' do
  title 'The macOS system must be configured with the SSH daemon ClientAliveInterval option set to 900 or less.'
  desc 'If SSH is not being used, this is Not Applicable.

The SSH daemon "ClientAliveInterval" option must be set correctly. To check the idle timeout setting for SSH sessions, run the following:

/usr/bin/grep ^ClientAliveInterval /etc/ssh/sshd_config

If the setting is not "900" or less, this is a finding.'
  desc 'check', 'The SSH daemon "ClientAliveInterval" option must be set correctly. To check the idle timeout setting for SSH sessions, run the following:

/usr/bin/grep ^ClientAliveInterval /etc/ssh/sshd_config

If the setting is not "900" or less, this is a finding.'
  desc 'fix', %q(To ensure that "ClientAliveInterval" is set correctly, run the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/.*ClientAliveInterval.*/ClientAliveInterval 900/' /etc/ssh/sshd_config)
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33709r607179_chk'
  tag severity: 'medium'
  tag gid: 'V-230764'
  tag rid: 'SV-230764r599842_rule'
  tag stig_id: 'APPL-11-000051'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-33682r607180_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
