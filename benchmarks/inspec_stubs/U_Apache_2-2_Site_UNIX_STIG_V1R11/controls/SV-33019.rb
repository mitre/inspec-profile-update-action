control 'SV-33019' do
  title 'Private web servers must require certificates issued from a DoD-authorized Certificate Authority.'
  desc 'Web sites requiring authentication within the DoD must utilize PKI as an authentication mechanism for web users. Information systems residing behind web servers requiring authorization based on individual identity must use the identity provided by certificate-based authentication to support access control decisions.'
  desc 'check', 'To view the SSLVerifyClient value enter the following command:

grep "SSLVerifyClient" /usr/local/apache2/conf/httpd.conf.

If the value of SSLVerifyClient is not set to “require”, this is a finding.'
  desc 'fix', 'Edit the httpd.conf file and set the value of SSLVerifyClient to "require".'
  impact 0.5
  ref 'DPMS Target Apache Site 2.x'
  tag check_id: 'C-33701r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6531'
  tag rid: 'SV-33019r1_rule'
  tag stig_id: 'WG140 A22'
  tag gtitle: 'WG140'
  tag fix_id: 'F-29335r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
