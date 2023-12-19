control 'SV-35222' do
  title "The system's access control program must be configured to grant or deny system access to specific hosts."
  desc "If the system's access control program is not configured with appropriate rules for allowing and denying access to system network resources, services may be accessible to unauthorized hosts."
  desc 'check', %q(Check for the existence of the /etc/hosts.allow and /etc/hosts.deny files (normally located within the /etc directory).
# find /etc -type f -name hosts.allow -o -name hosts.deny | xargs -n1 ls -lL

If either file does not exist, this is a finding.

Check for the presence of a deny by default entry.
cat <path>/hosts.deny | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' |grep -v "^#" | egrep "ALL: ALL"

If the ALL: ALL entry is not present the hosts.deny file, any TCP service from a host or network not matching other rules will be allowed access. If the entry is not in hosts.deny, this is a finding.)
  desc 'fix', 'Edit the <path>/hosts.allow and <path/hosts.deny files to configure access restrictions.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36733r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12030'
  tag rid: 'SV-35222r1_rule'
  tag stig_id: 'GEN006620'
  tag gtitle: 'GEN006620'
  tag fix_id: 'F-32114r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1, ECCD-1, ECCD-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
