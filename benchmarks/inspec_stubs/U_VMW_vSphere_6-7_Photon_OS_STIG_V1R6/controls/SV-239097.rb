control 'SV-239097' do
  title 'The Photon operating system must store only encrypted representations of passwords.'
  desc 'Passwords must be protected at all times via strong, one-way encryption. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. If they are encrypted with a weak cipher, those passwords are much more vulnerable to offline brute forcing attacks.'
  desc 'check', 'At the command line, execute the following command:

# grep password /etc/pam.d/system-password|grep --color=always "sha512"

If the output does not include "sha512", this is a finding.'
  desc 'fix', 'Open /etc/applmgmt/appliance/system-password with a text editor.

Add the following argument (sha512) to the password line:

password required pam_unix.so sha512 shadow try_first_pass

Save and close.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42308r675097_chk'
  tag severity: 'medium'
  tag gid: 'V-239097'
  tag rid: 'SV-239097r877397_rule'
  tag stig_id: 'PHTN-67-000025'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-42267r816612_fix'
  tag 'documentable'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
