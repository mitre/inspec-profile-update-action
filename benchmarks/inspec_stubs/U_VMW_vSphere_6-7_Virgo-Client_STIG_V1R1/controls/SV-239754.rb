control 'SV-239754' do
  title 'vSphere Client must have Multipurpose Internet Mail Extensions (MIME) that invoke OS shell programs disabled.'
  desc 'MIME mappings tell vSphere Client what type of program various file types and extensions are and what external utilities or programs are needed to execute the file type. 

By ensuring that various shell script MIME types are not included in web.xml, the server is protected against malicious users tricking the server into executing shell command files.'
  desc 'check', "At the command prompt, execute the following command:

# grep -En '(x-csh<)|(x-sh<)|(x-shar<)|(x-ksh<)' /usr/lib/vmware-vsphere-client/server/configuration/conf/web.xml

If the command produces any output, this is a finding."
  desc 'fix', 'Open /usr/lib/vmware-vsphere-client/server/configuration/conf/web.xml in a text editor. 

Remove any and all of the following nodes lines:

<mime-type>application/x-csh</mime-type>
<mime-type>application/x-shar</mime-type>
<mime-type>application/x-sh</mime-type>
<mime-type>application/x-ksh</mime-type>'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Virgo-Client'
  tag check_id: 'C-42987r679487_chk'
  tag severity: 'medium'
  tag gid: 'V-239754'
  tag rid: 'SV-239754r679489_rule'
  tag stig_id: 'VCFL-67-000013'
  tag gtitle: 'SRG-APP-000141-WSR-000081'
  tag fix_id: 'F-42946r679488_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
