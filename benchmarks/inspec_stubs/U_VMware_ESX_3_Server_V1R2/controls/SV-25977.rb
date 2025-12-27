control 'SV-25977' do
  title 'The /etc/nsswitch.conf file must not have an extended ACL.'
  desc 'The nsswitch.conf file (or equivalent) configures the source of a variety of system security information including account, group, and host lookups.  Malicious changes could prevent the system from functioning or compromise system security.'
  desc 'check', 'Verify /etc/nsswitch.conf has no extended ACL.

Procedure:
# ls -l /etc/nsswitch.conf
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the /etc/nsswitch.conf file.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27499r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22330'
  tag rid: 'SV-25977r1_rule'
  tag stig_id: 'GEN001374'
  tag gtitle: 'GEN001374'
  tag fix_id: 'F-26120r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
