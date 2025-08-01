control 'SV-241648' do
  title 'tc Server UI must not have any symbolic links in the web content directory tree.'
  desc "A web server is designed to deliver content and execute scripts or applications on the request of a client or user. Containing user requests to files in the directory tree of the hosted web application and limiting the execution of scripts and applications guarantees that the user is not accessing information protected outside the application's realm.

By checking that no symbolic links exist in the document root, the web server is protected from users jumping outside the hosted application directory tree and gaining access to the other directories, including the system root."
  desc 'check', "At the command prompt, execute the following command:

ls -lR /usr/lib/vmware-vcops/tomcat-web-app | grep '^l'

If the command produces any output other than the expected result below, this is a finding.

Expected Result:
lrwxrwxrwx 1 admin admin   33 Mar  6 03:37 logs -> /storage/log/vcops/log/product-ui
lrwxrwxrwx  1 admin admin        47 Mar  6 03:37 vcops-web-ent -> /usr/lib/vmware-vcops/tomcat-web-app/webapps/ui"
  desc 'fix', 'At the command prompt, execute the following command:

Note: Replace <file_name> for the name of any files that were returned.

unlink <file_name>

Repeat the commands for each file that was returned.'
  impact 0.7
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44924r684159_chk'
  tag severity: 'high'
  tag gid: 'V-241648'
  tag rid: 'SV-241648r879587_rule'
  tag stig_id: 'VROM-TC-000415'
  tag gtitle: 'SRG-APP-000141-WSR-000087'
  tag fix_id: 'F-44883r683805_fix'
  tag 'documentable'
  tag legacy: ['SV-99581', 'V-88931']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
