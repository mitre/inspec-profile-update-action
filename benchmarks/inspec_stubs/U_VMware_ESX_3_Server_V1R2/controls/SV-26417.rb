control 'SV-26417' do
  title 'The /etc/nsswitch.conf file must be owned by root.'
  desc 'The nsswitch.conf file (or equivalent) configures the source of a variety of system security information including account, group, and host lookups.  Malicious changes could prevent the system from functioning or compromise system security.'
  desc 'check', 'Verify the /etc/nsswitch.conf file is owned by root.

Procedure:
# ls -l /etc/nsswitch.conf
If the file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the /etc/nsswitch.conf file to root.

# chown root /etc/nsswitch.conf'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27496r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22327'
  tag rid: 'SV-26417r1_rule'
  tag stig_id: 'GEN001371'
  tag gtitle: 'GEN001371'
  tag fix_id: 'F-23604r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
