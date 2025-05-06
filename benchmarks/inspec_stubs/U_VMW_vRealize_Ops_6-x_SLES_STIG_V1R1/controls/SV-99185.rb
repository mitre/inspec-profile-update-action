control 'SV-99185' do
  title 'Files executed through a mail aliases file must have mode 0755 or less permissive.'
  desc 'If a file executed through a mail alias file has permissions greater than 0755, it can be modified by an unauthorized user and may contain malicious code or instructions that could compromise the system.'
  desc 'check', 'Examine the contents of the "/etc/aliases" file:

# more /etc/aliases

Examine the aliases file for any directories or paths that may be utilized:

# ls -lL <file referenced from aliases>

Check the permissions for any paths referenced. 

If any file referenced from the aliases file has a mode more permissive than "0755", this is a finding.'
  desc 'fix', 'Use the chmod command to change the access permissions for files executed from the alias file:

# chmod 0755 <file referenced from aliases>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88227r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88535'
  tag rid: 'SV-99185r1_rule'
  tag stig_id: 'VROM-SL-000565'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-95277r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
