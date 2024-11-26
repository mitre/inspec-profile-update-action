control 'SV-241639' do
  title 'tc Server ALL must have Multipurpose Internet Mail Extensions (MIME) that invoke OS shell programs disabled.'
  desc "Controlling what a user of a hosted application can access is part of the security posture of the web server. Any time a user can access more functionality than is needed for the operation of the hosted application poses a security issue. A user with too much access can view information that is not needed for the user's job role, or the user could use the function in an unintentional manner.

A MIME tells the web server what type of program various file types and extensions are and what external utilities or programs are needed to execute the file type.

tc Server configures MIME types in the web.xml file. By ensuring that “sh”, “csh”, and “shar” MIME types are not included in web.xml, the server is protected against malicious users tricking the server into executing shell command files."
  desc 'check', "At the command prompt, execute the following command:

find / -name 'web.xml' -print0 | xargs -0r grep -HEn '(x-csh<)|(x-sh<)|(x-shar<)|(x-ksh<)'

If the command produces any output, this is a finding."
  desc 'fix', 'Navigate to a file that was listed.

Open the file in a text editor.

Delete any of the following types:

application/x-sh
application/x-shar
application/x-csh
application/x-ksh'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44915r683777_chk'
  tag severity: 'medium'
  tag gid: 'V-241639'
  tag rid: 'SV-241639r879587_rule'
  tag stig_id: 'VROM-TC-000370'
  tag gtitle: 'SRG-APP-000141-WSR-000081'
  tag fix_id: 'F-44874r683778_fix'
  tag 'documentable'
  tag legacy: ['SV-99563', 'V-88913']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
