control 'SV-219314' do
  title 'The Ubuntu operating system must not allow unattended or automatic login via ssh.'
  desc 'Failure to restrict system access to authenticated users negatively impacts Ubuntu operating system security.'
  desc 'check', %q(Verify that unattended or automatic login via ssh is disabled.

Check that unattended or automatic login via ssh is disabled with the following command:

# egrep '(Permit(.*?)(Passwords|Environment))' /etc/ssh/sshd_config

PermitEmptyPasswords no
PermitUserEnvironment no

If "PermitEmptyPasswords" or "PermitUserEnvironment" keywords are not set to "no", are missing completely, or they are commented out, this is a finding.)
  desc 'fix', 'Configure the Ubuntu operating system to allow the SSH daemon to not allow unattended or automatic login to the system.

Add or edit the following lines in the "/etc/ssh/sshd_config" file:

PermitEmptyPasswords no
PermitUserEnvironment no

In order for the changes to take effect, the SSH daemon must be restarted.

# sudo systemctl restart sshd.service'
  impact 0.7
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-21039r305270_chk'
  tag severity: 'high'
  tag gid: 'V-219314'
  tag rid: 'SV-219314r610963_rule'
  tag stig_id: 'UBTU-18-010424'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-21038r305271_fix'
  tag 'documentable'
  tag legacy: ['SV-109955', 'V-100851']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
