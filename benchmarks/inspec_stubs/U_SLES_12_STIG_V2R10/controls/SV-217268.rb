control 'SV-217268' do
  title 'The SUSE operating system must not allow automatic logon via SSH.'
  desc 'Failure to restrict system access via SSH to authenticated users negatively impacts SUSE operating system security.'
  desc 'check', 'Verify the SUSE operating system disables automatic logon via SSH.

Check that automatic logon via SSH is disabled with the following command:

# sudo grep -i "permitemptypasswords" /etc/ssh/sshd_config

PermitEmptyPasswords no

If "PermitEmptyPasswords" is not set to "no", is missing completely, or is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system disables automatic logon via SSH.

Add or edit the following line in the "/etc/ssh/sshd_config" file:

PermitEmptyPasswords no'
  impact 0.7
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18496r369960_chk'
  tag severity: 'high'
  tag gid: 'V-217268'
  tag rid: 'SV-217268r877377_rule'
  tag stig_id: 'SLES-12-030150'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-18494r369961_fix'
  tag 'documentable'
  tag legacy: ['V-77451', 'SV-92147']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
