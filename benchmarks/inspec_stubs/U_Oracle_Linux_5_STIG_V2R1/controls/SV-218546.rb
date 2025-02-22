control 'SV-218546' do
  title 'The system must not use .forward files.'
  desc 'The .forward file allows users to automatically forward mail to another system. Use of .forward files could allow the unauthorized forwarding of mail and could potentially create mail loops which could degrade system performance.'
  desc 'check', 'Check forwarding capability from sendmail.

Procedure:
grep "O ForwardPath" /etc/mail/sendmail.cf

If the entry contains a file path, this is a finding.

Search for any .forward in users home directories on the system by:

# for pwline in `cut -d: -f1,6 /etc/passwd`; do homedir=`echo ${pwline}|cut -d: -f2`;username=`echo ${pwline} | cut -d: -f1`;echo $username `stat -c %n $homedir/.forward 2>null`; done|egrep "\\.forward"

If any users have a .forward file in their home directory, this is a finding.'
  desc 'fix', "Disable forwarding for sendmail and remove .forward files from the system

Procedure:
Edit the /etc/mail/sendmail.mc file to change the ForwardPath entry to a null path by adding the line
define(`confFORWARD_PATH',`')
rebuild the sendmail.cf file.

Remove all .forward files on the system
# find / -name .forward -delete"
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20021r555836_chk'
  tag severity: 'medium'
  tag gid: 'V-218546'
  tag rid: 'SV-218546r603259_rule'
  tag stig_id: 'GEN004580'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20019r555837_fix'
  tag 'documentable'
  tag legacy: ['V-4385', 'SV-62713']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
