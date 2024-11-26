control 'SV-240798' do
  title 'tc Server VCO must not have any symbolic links in the web content directory tree.'
  desc "A web server is designed to deliver content and execute scripts or applications on the request of a client or user. Containing user requests to files in the directory tree of the hosted web application and limiting the execution of scripts and applications guarantees that the user is not accessing information protected outside the application's realm. 

By checking that no symblic links exist in the document root, the web server is protected from users jumping outside the hosted application directory tree and gaining access to the other directories, including the system root."
  desc 'check', "At the command prompt, execute the following command:

ls -lR /usr/lib/vco/configuration/webapps | grep '^l'

If the command produces any output, this is a finding."
  desc 'fix', 'At the command prompt, execute the following commands:

Note: Replace <file_name> for the name of any files that were returned.

unlink <file_name>

Repeat the commands for each file that was returned.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44031r674136_chk'
  tag severity: 'medium'
  tag gid: 'V-240798'
  tag rid: 'SV-240798r879587_rule'
  tag stig_id: 'VRAU-TC-000410'
  tag gtitle: 'SRG-APP-000141-WSR-000087'
  tag fix_id: 'F-43990r674137_fix'
  tag 'documentable'
  tag legacy: ['SV-100679', 'V-90029']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
