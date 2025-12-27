control 'SV-238218' do
  title 'The Ubuntu operating system must not allow unattended or automatic login via SSH.'
  desc 'Failure to restrict system access to authenticated users negatively impacts Ubuntu operating system security.'
  desc 'check', %q(Verify that unattended or automatic login via SSH is disabled with the following command: 
 
$ egrep '(Permit(.*?)(Passwords|Environment))' /etc/ssh/sshd_config 
 
PermitEmptyPasswords no 
PermitUserEnvironment no 
 
If "PermitEmptyPasswords" or "PermitUserEnvironment" keywords are not set to "no", are missing completely, or are commented out, this is a finding.)
  desc 'fix', 'Configure the Ubuntu operating system to allow the SSH daemon to not allow unattended or automatic login to the system. 
 
Add or edit the following lines in the "/etc/ssh/sshd_config" file: 
 
PermitEmptyPasswords no 
PermitUserEnvironment no 
 
Restart the SSH daemon for the changes to take effect: 
 
$ sudo systemctl restart sshd.service'
  impact 0.7
  ref 'DPMS Target Canonical Ubuntu 20.04 LTS'
  tag check_id: 'C-41428r653827_chk'
  tag severity: 'high'
  tag gid: 'V-238218'
  tag rid: 'SV-238218r653829_rule'
  tag stig_id: 'UBTU-20-010047'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-41387r653828_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
