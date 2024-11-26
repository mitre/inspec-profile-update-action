control 'SV-77723' do
  title 'The system must prohibit the reuse of passwords within five iterations.'
  desc "If a user, or root, used the same password continuously or was allowed to change it back shortly after being forced to change it to something else, it would provide a potential intruder with the opportunity to keep guessing at one user's password until it was guessed correctly."
  desc 'check', 'To verify the remember setting, run the following command: 

# grep -i "^password" /etc/pam.d/passwd | grep sufficient

If the remember setting is not set or is not "remember=5", this is a finding.'
  desc 'fix', 'To set the remember option, add or correct the following line in "/etc/pam.d/passwd":

password   sufficient   /lib/security/$ISA/pam_unix.so use_authtok nullok shadow sha512 remember=5'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63967r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63233'
  tag rid: 'SV-77723r1_rule'
  tag stig_id: 'ESXI-06-000032'
  tag gtitle: 'SRG-OS-000077-VMM-000440'
  tag fix_id: 'F-69151r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
