control 'SV-239663' do
  title 'The Security Token Service must have Multipurpose Internet Mail Extensions (MIME) that invoke OS shell programs disabled.'
  desc 'MIME mappings tell the Security Token Service what type of program various file types and extensions are and what external utilities or programs are needed to execute the file type. By ensuring that various shell script MIME types are not included in "web.xml", the server is protected against malicious users tricking the server into executing shell command files.'
  desc 'check', "Connect to the PSC, whether external or embedded.

At the command prompt, execute the following command:

# grep -En '(x-csh<)|(x-sh<)|(x-shar<)|(x-ksh<)' /usr/lib/vmware-sso/vmware-sts/conf/web.xml

If the command produces any output, this is a finding."
  desc 'fix', 'Connect to the PSC, whether external or embedded.

Open /usr/lib/vmware-sso/vmware-sts/conf/web.xml in a text editor.

Remove the parent <mime-mapping> node of any line returned from the check.

Example:

<mime-mapping>
    <extension>csh</extension>
    <mime-type>application/x-csh</mime-type>
</mime-mapping>'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 STS Tomcat'
  tag check_id: 'C-42896r816712_chk'
  tag severity: 'medium'
  tag gid: 'V-239663'
  tag rid: 'SV-239663r879587_rule'
  tag stig_id: 'VCST-67-000012'
  tag gtitle: 'SRG-APP-000141-WSR-000081'
  tag fix_id: 'F-42855r816713_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
