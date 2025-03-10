control 'SV-254196' do
  title 'Nutanix AOS must not allow an unattended or automatic logon to the system.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  desc 'check', 'Confirm Nutanix AOS does not allow users to override environment variables to the SSH daemon.

Check for the value of the "PermitUserEnvironment" keyword with the following command:

$ sudo grep -i permituserenvironment /etc/ssh/sshd_config
PermitUserEnvironment no

If the "PermitUserEnvironment" keyword is not set to "no", is missing, or is commented out, this is a finding.

$ sudo grep -i hostbasedauthentication /etc/ssh/sshd_config
HostbasedAuthentication no

If the "HostbasedAuthentication" keyword is not set to "no", is missing, or is commented out, this is a finding.'
  desc 'fix', 'Configure Nutanix AOS to not allow users to override environment variables to the SSH daemon by running the following command.

$ sudo salt-call state.sls security/CVM/sshdCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57681r846674_chk'
  tag severity: 'medium'
  tag gid: 'V-254196'
  tag rid: 'SV-254196r846676_rule'
  tag stig_id: 'NUTX-OS-001090'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-57632r846675_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
