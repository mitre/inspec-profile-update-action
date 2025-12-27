control 'SV-99583' do
  title 'tc Server CaSa must not have any symbolic links in the web content directory tree.'
  desc "A web server is designed to deliver content and execute scripts or applications on the request of a client or user. Containing user requests to files in the directory tree of the hosted web application and limiting the execution of scripts and applications guarantees that the user is not accessing information protected outside the application's realm.

By checking that no symbolic links exist in the document root, the web server is protected from users jumping outside the hosted application directory tree and gaining access to the other directories, including the system root."
  desc 'check', "At the command prompt, execute the following command:

ls -lR /usr/lib/vmware-casa/casa-webapp | grep '^l'

If the command produces any output other than the expected result below, this is a finding.

Expected Result:
lrwxrwxrwx 1 admin admin   27 Mar  6 03:37 logs -> /storage/log/vcops/log/casa"
  desc 'fix', 'At the command prompt, execute the following command:

Note: Replace <file_name> for the name of any files that were returned.

unlink <file_name>

Repeat the commands for each file that was returned.'
  impact 0.7
  ref 'DPMS Target VMware vRealize Operations Manager 6.x tcServer'
  tag check_id: 'C-88625r1_chk'
  tag severity: 'high'
  tag gid: 'V-88933'
  tag rid: 'SV-99583r1_rule'
  tag stig_id: 'VROM-TC-000420'
  tag gtitle: 'SRG-APP-000141-WSR-000087'
  tag fix_id: 'F-95675r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
