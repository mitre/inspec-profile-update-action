control 'SV-45868' do
  title 'The system must not use .forward files.'
  desc 'The .forward file allows users to automatically forward mail to another system. Use of .forward files could allow the unauthorized forwarding of mail and could potentially create mail loops which could degrade system performance.'
  desc 'check', 'Determine if sendmail is installed 
# rpm -qa | grep -i sendmail

This check only applies to systems that have the sendmail package installed.  
Check forwarding capability from sendmail.

Procedure:
grep "0 ForwardPath" /etc/mail/sendmail.cf

If the entry contains a file path, this is a finding.

Search for any .forward in users home directories on the system by:

# for pwline in `cut -d: -f1,6 /etc/passwd`; do homedir=`echo ${pwline}|cut -d: -f2`;username=`echo ${pwline} | cut -d: -f1`;echo $username `stat -c %n $homedir/.forward 2>/dev/null`; done|egrep "\\.forward"

If any users have a .forward file in their home directory, this is a finding.'
  desc 'fix', "Disable forwarding for sendmail and remove .forward files from the system

Procedure:
Edit the /etc/mail/sendmail.mc file to change the ForwardPath entry to a null path by adding the line
define(`confFORWARD_PATH`,`')
rebuild the sendmail.cf file.

Remove all .forward files on the system
# find / -name .forward -delete"
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43176r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4385'
  tag rid: 'SV-45868r1_rule'
  tag stig_id: 'GEN004580'
  tag gtitle: 'GEN004580'
  tag fix_id: 'F-39246r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
