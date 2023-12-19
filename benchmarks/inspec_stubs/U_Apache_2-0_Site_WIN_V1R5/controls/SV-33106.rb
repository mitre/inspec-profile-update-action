control 'SV-33106' do
  title 'Private web servers must require certificates issued from a DoD-authorized Certificate Authority.'
  desc 'Web sites requiring authentication within the DoD must utilize PKI as an authentication mechanism for web users. Information systems residing behind web servers requiring authorization based on individual identity must use the identity provided by certificate-based authentication to support access control decisions.'
  desc 'check', 'Locate the Apache httpd.conf file.

If unable to locate the file, perform a search of the system to find the location of the file.

Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directive: SSLVerifyClient

If SSLVerifyClient is not set to “require” this is a finding as the client is not required to present a valid certificate.'
  desc 'fix', 'Set the SSLVerifyClient directive to "require".'
  impact 0.5
  ref 'DPMS Target Apache Site 2.0'
  tag check_id: 'C-33767r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6531'
  tag rid: 'SV-33106r1_rule'
  tag stig_id: 'WG140 W22'
  tag gtitle: 'WG140'
  tag fix_id: 'F-29404r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'IATS-1, IATS-2'
end
