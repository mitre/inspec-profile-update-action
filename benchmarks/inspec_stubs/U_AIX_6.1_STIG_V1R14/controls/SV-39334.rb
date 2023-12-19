control 'SV-39334' do
  title 'The /etc/nsswitch.conf file must not have an extended ACL.'
  desc 'The nsswitch.conf file (or equivalent) configures the source of a variety of system security information including account, group, and host lookups.  Malicious changes could prevent the system from functioning or compromise system security.'
  desc 'check', 'Verify /etc/nsswitch.conf has no extended ACL. 

AIX does not use the /etc/nsswitch.conf file.  This check is not applicable.

Procedure: 
# aclget /etc/nsswitch.conf 

If extended permissions are enabled, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the /etc/nsswitch.conf file. 

# acledit /etc/nsswitch.conf'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38282r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22330'
  tag rid: 'SV-39334r1_rule'
  tag stig_id: 'GEN001374'
  tag gtitle: 'GEN001374'
  tag fix_id: 'F-33569r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
