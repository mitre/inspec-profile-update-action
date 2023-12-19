control 'SV-239692' do
  title 'vSphere UI must have Multipurpose Internet Mail Extensions (MIME) that invoke OS shell programs disabled.'
  desc 'MIME mappings tell the vSphere UI what type of program various file types and extensions are and what external utilities or programs are needed to execute the file type. By ensuring that various shell script MIME types are not included in web.xml, the server is protected against malicious users tricking the server into executing shell command files.'
  desc 'check', "At the command prompt, execute the following command:

# grep -En '(x-csh<)|(x-sh<)|(x-shar<)|(x-ksh<)' /usr/lib/vmware-vsphere-ui/server/conf/web.xml

If the command produces any output, this is a finding."
  desc 'fix', 'Navigate to and open /usr/lib/vmware-vsphere-ui/server/conf/web.xml. 

Remove any and all of the following nodes lines:

<mime-type>application/x-csh</mime-type>
<mime-type>application/x-shar</mime-type>
<mime-type>application/x-sh</mime-type>
<mime-type>application/x-ksh</mime-type>'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 UI Tomcat'
  tag check_id: 'C-42925r679180_chk'
  tag severity: 'medium'
  tag gid: 'V-239692'
  tag rid: 'SV-239692r879587_rule'
  tag stig_id: 'VCUI-67-000011'
  tag gtitle: 'SRG-APP-000141-WSR-000081'
  tag fix_id: 'F-42884r679181_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
