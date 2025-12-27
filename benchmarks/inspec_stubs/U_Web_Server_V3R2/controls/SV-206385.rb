control 'SV-206385' do
  title 'Users and scripts running on behalf of users must be contained to the document root or home directory tree of the web server.'
  desc "A web server is designed to deliver content and execute scripts or applications on the request of a client or user.  Containing user requests to files in the directory tree of the hosted web application and limiting the execution of scripts and applications guarantees that the user is not accessing information protected outside the application's realm.  

The web server must also prohibit users from jumping outside the hosted application directory tree through access to the user's home directory, symbolic links or shortcuts, or through search paths for missing files."
  desc 'check', "Review the web server documentation and configuration to determine where the document root or home directory for each application hosted by the web server is located.

Verify that users of the web server applications, and any scripts running on the user's behalf, are contained to each application's domain.

If users of the web server applications, and any scripts running on the user's behalf, are not contained, this is a finding."
  desc 'fix', "Configure the web server to contain users and scripts to each hosted application's domain."
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6646r377747_chk'
  tag severity: 'medium'
  tag gid: 'V-206385'
  tag rid: 'SV-206385r879587_rule'
  tag stig_id: 'SRG-APP-000141-WSR-000087'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-6646r377748_fix'
  tag 'documentable'
  tag legacy: ['SV-54281', 'V-41704']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
