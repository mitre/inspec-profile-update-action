control 'SV-215189' do
  title 'AIX system must prevent the root account from directly logging in except from the system console.'
  desc 'Limiting the root account direct logins to only system consoles protects the root account from direct unauthorized access from a non-console device.

A common attack method of potential hackers is to obtain the root password.

To avoid this type of attack, disable direct access to the root ID and then require system administrators to obtain root privileges by using the su - command. In addition to permitting removal of the root user as a point of attack, restricting direct root access permits monitoring which users gained root access, as well as the time of their action. Do this by viewing the /var/adm/sulog file. Another alternative is to enable system auditing, which will report this type of activity.

To disable remote login access for the root user, edit the /etc/security/user file. Specify False as the rlogin value on the entry for root.'
  desc 'check', 'Check the remote login ability of the root account using command: 
# lsuser -a rlogin root 
root rlogin=false

If the "rlogin" value is not "false", this is a finding.'
  desc 'fix', 'From the command prompt, run the following command to set "rlogin=false" for the root stanza in "/etc/security/user":
# chsec -f /etc/security/user -s root -a rlogin=false'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16387r294018_chk'
  tag severity: 'medium'
  tag gid: 'V-215189'
  tag rid: 'SV-215189r508663_rule'
  tag stig_id: 'AIX7-00-001030'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16385r294019_fix'
  tag 'documentable'
  tag legacy: ['SV-101677', 'V-91579']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
