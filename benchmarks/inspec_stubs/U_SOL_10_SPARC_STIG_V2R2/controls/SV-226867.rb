control 'SV-226867' do
  title 'The "at" directory must not have an extended ACL.'
  desc 'If the "at" directory has an extended ACL, unauthorized users could be allowed to view or to edit files containing sensitive information within the "at" directory.  Unauthorized modifications could result in Denial of Service to authorized "at" jobs.'
  desc 'check', 'Check the permissions of the directory.
# ls -lLd /var/spool/cron/atjobs
If the permissions include a "+", the directory has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /var/spool/cron/atjobs'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29029r484885_chk'
  tag severity: 'medium'
  tag gid: 'V-226867'
  tag rid: 'SV-226867r603265_rule'
  tag stig_id: 'GEN003410'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29017r484886_fix'
  tag 'documentable'
  tag legacy: ['V-22395', 'SV-26566']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
