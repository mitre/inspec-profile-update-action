control 'SV-230766' do
  title 'The macOS system must be configured with the SSH daemon LoginGraceTime set to 30 or less.'
  desc 'If SSH is not being used, this is Not Applicable.

The SSH daemon "LoginGraceTime" must be set correctly. To check the amount of time that a user can log on through SSH, run the following command:

/usr/bin/grep ^LoginGraceTime /etc/ssh/sshd_config

If the value is not set to "30" or less, this is a finding.'
  desc 'check', 'The SSH daemon "LoginGraceTime" must be set correctly. To check the amount of time that a user can log on through SSH, run the following command:

/usr/bin/grep ^LoginGraceTime /etc/ssh/sshd_config

If the value is not set to "30" or less, this is a finding.'
  desc 'fix', %q(To ensure that "LoginGraceTime" is configured correctly, run the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/.*LoginGraceTime.*/LoginGraceTime 30/' /etc/ssh/sshd_config)
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33711r607185_chk'
  tag severity: 'medium'
  tag gid: 'V-230766'
  tag rid: 'SV-230766r599842_rule'
  tag stig_id: 'APPL-11-000053'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-33684r607186_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
