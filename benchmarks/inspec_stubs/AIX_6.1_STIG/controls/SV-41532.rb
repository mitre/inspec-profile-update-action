control 'SV-41532' do
  title "The system's access control program must be configured to grant or deny system access to specific hosts."
  desc "If the system's access control program is not configured with appropriate rules for allowing and denying access to system network resources, services may be accessible to unauthorized hosts."
  desc 'check', 'Check for the existence of the /etc/hosts.allow and /etc/hosts.deny files.

Procedure:
# ls -la /etc/hosts.allow
# ls -la /etc/hosts.deny

If either file does not exist, this is a finding.

Check for the presence of a default deny entry.

Procedure:
# grep "ALL: ALL" /etc/hosts.deny

If the "ALL: ALL" entry is not present in the /etc/hosts.deny file, any TCP service from a host or network not matching other rules will be allowed access.  If the entry is not in /etc/hosts.deny, this is a finding.'
  desc 'fix', 'Edit the /etc/hosts.allow and /etc/hosts.deny files to configure access restrictions.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-7993r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12030'
  tag rid: 'SV-41532r1_rule'
  tag stig_id: 'GEN006620'
  tag gtitle: 'GEN006620'
  tag fix_id: 'F-11287r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
