control 'SV-214368' do
  title 'Users and scripts running on behalf of users must be contained to the document root or home directory tree of the Apache web server.'
  desc "A web server is designed to deliver content and execute scripts or applications on the request of a client or user. Containing user requests to files in the directory tree of the hosted web application and limiting the execution of scripts and applications guarantees that the user is not accessing information protected outside the application's realm.

The web server must also prohibit users from jumping outside the hosted application directory tree through access to the user's home directory, symbolic links or shortcuts, or through search paths for missing files."
  desc 'check', "Review the <'INSTALLED PATH'>\\conf\\httpd.conf file and search for the following directive:

Directory

For every root directory entry (i.e., <Directory />), verify the following exists. If it does not, this is a finding:

Require all denied

If the statement above is not found in the root directory statement, this is a finding."
  desc 'fix', "Edit the <'INSTALLED PATH'>\\conf\\httpd.conf file and set the root directory directive as follows:

Directory

Require all denied"
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Site'
  tag check_id: 'C-15579r277845_chk'
  tag severity: 'medium'
  tag gid: 'V-214368'
  tag rid: 'SV-214368r395853_rule'
  tag stig_id: 'AS24-W2-000350'
  tag gtitle: 'SRG-APP-000141-WSR-000087'
  tag fix_id: 'F-15577r277846_fix'
  tag 'documentable'
  tag legacy: ['SV-102599', 'V-92511']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
