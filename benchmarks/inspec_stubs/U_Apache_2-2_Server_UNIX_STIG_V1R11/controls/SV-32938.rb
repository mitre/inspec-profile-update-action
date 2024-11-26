control 'SV-32938' do
  title 'Web server system files must conform to minimum file permission requirements.'
  desc 'This check verifies that the key web server system configuration files are owned by the SA or the web administrator controlled account. These same files that control the configuration of the web server, and thus its behavior, must also be accessible by the account that runs the web service. If these files are altered by a malicious user, the web server would no longer be under the control of its managers and owners; properties in the web server configuration could be altered to compromise the entire server platform.'
  desc 'check', 'Apache directory and file permissions and ownership should be set per the following table.. The installation directories may vary from one installation to the next.  If used, the WebAmins group should contain only accounts of persons authorized to manage the web server configuration, otherwise the root group should own all Apache files and directories. 

Note: This check also applies to any other directory where CGI scripts are located. There may be additional directories based the local implementation, and permissions should apply to directories of similar content. Ex. all web content directories should follow the permissions for /htdocs.

If the files and directories are not set to the following permissions or more restrictive, this is a finding.

To locate the ServerRoot directory enter the following command.
grep ^ ServerRoot /usr/local/apache2/conf/httpd.conf

/Server
root dir
apache	      root	WebAdmin	771/660

/apache/cgi-bin    root	WebAdmin	775/775
/apache/bin	       root	WebAdmin	550/550
/apache/config     root	WebAdmin	770/660
/apache/htdocs    root	WebAdmin	775/664
/apache/logs       root	WebAdmin	750/640

NOTE:  The permissions are noted as directories / files.'
  desc 'fix', 'Use the chmod command to set permissions on the web server system directories and files as follows.

root dir
apache	      root	WebAdmin	771/660
/apache/cgi-bin    root	WebAdmin	775/775
/apache/bin	       root	WebAdmin	550/550
/apache/config     root	WebAdmin	770/660
/apache/htdocs    root	WebAdmin	775/664
/apache/logs       root	WebAdmin	750/640'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33630r2_chk'
  tag severity: 'medium'
  tag gid: 'V-2259'
  tag rid: 'SV-32938r2_rule'
  tag stig_id: 'WG300 A22'
  tag gtitle: 'WG300'
  tag fix_id: 'F-29268r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
