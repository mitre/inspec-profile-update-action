control 'SV-38820' do
  title 'The /etc/syslog.conf file must not have an extended ACL.'
  desc 'Unauthorized users must not be allowed to access or modify the /etc/syslog.conf file.'
  desc 'check', 'Check the permissions of the syslog configuration file.
# aclget /etc/syslog.conf
If the extended attributes are not disabled, this is a finding'
  desc 'fix', 'Remove the extended ACL from the syslog.conf file and change extended attributes to disabled.

#acledit /etc/syslog.conf'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37064r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22454'
  tag rid: 'SV-38820r1_rule'
  tag stig_id: 'GEN005395'
  tag gtitle: 'GEN005395'
  tag fix_id: 'F-32330r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
