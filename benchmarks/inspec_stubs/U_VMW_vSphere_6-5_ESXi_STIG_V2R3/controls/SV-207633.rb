control 'SV-207633' do
  title 'The ESXi host must prohibit the reuse of passwords within five iterations.'
  desc "If a user, or root, used the same password continuously or was allowed to change it back shortly after being forced to change it to something else, it would provide a potential intruder with the opportunity to keep guessing at one user's password until it was guessed correctly."
  desc 'check', 'From an SSH session connected to the ESXi host, or from the ESXi shell, run the following command:

# grep -i "^password" /etc/pam.d/passwd | grep sufficient

If the remember setting is not set or is not "remember=5", this is a finding.'
  desc 'fix', 'From an SSH session connected to the ESXi host, or from the ESXi shell, add or correct the following line in “/etc/pam.d/passwd”:

password sufficient /lib/security/$ISA/pam_unix.so use_authtok nullok shadow sha512 remember=5'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7888r364298_chk'
  tag severity: 'medium'
  tag gid: 'V-207633'
  tag rid: 'SV-207633r378763_rule'
  tag stig_id: 'ESXI-65-000032'
  tag gtitle: 'SRG-OS-000077-VMM-000440'
  tag fix_id: 'F-7888r364299_fix'
  tag 'documentable'
  tag legacy: ['SV-104097', 'V-94011']
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
