control 'SV-217269' do
  title 'The SUSE operating system must not allow users to override SSH environment variables.'
  desc 'SSH environment options potentially allow users to bypass access restriction in some configurations.'
  desc 'check', 'Verify the SUSE operating system disables unattended via SSH.

Check that unattended logon via SSH is disabled with the following command:

# sudo grep -i "permituserenvironment" /etc/ssh/sshd_config

PermitUserEnvironment no

If the "PermitUserEnvironment" keyword is not set to "no", is missing completely, or is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system disables unattended logon via SSH.

Add or edit the following lines in the "/etc/ssh/sshd_config" file:

PermitUserEnvironment no'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18497r369963_chk'
  tag severity: 'medium'
  tag gid: 'V-217269'
  tag rid: 'SV-217269r646747_rule'
  tag stig_id: 'SLES-12-030151'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-18495r369964_fix'
  tag 'documentable'
  tag legacy: ['V-99011', 'SV-108115']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
