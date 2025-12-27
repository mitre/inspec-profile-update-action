control 'SV-230765' do
  title 'The macOS system must be configured with the SSH daemon ClientAliveCountMax option set to 0.'
  desc 'If SSH is not being used, this is Not Applicable.

The SSH daemon "ClientAliveCountMax" option must be set correctly. To verify the SSH idle timeout will occur when the "ClientAliveCountMax" is set, run the following command:

/usr/bin/grep ^ClientAliveCountMax /etc/ssh/sshd_config

If the setting is not "ClientAliveCountMax 0", this is a finding.'
  desc 'check', 'The SSH daemon "ClientAliveCountMax" option must be set correctly. To verify the SSH idle timeout will occur when the "ClientAliveCountMax" is set, run the following command:

/usr/bin/grep ^ClientAliveCountMax /etc/ssh/sshd_config

If the setting is not "ClientAliveCountMax 0", this is a finding.'
  desc 'fix', %q(To ensure that the SSH idle timeout occurs precisely when the "ClientAliveCountMax" is set, run the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/.*ClientAliveCountMax.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config)
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33710r607182_chk'
  tag severity: 'medium'
  tag gid: 'V-230765'
  tag rid: 'SV-230765r599842_rule'
  tag stig_id: 'APPL-11-000052'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-33683r607183_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
