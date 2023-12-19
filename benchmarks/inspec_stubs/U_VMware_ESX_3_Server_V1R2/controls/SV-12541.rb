control 'SV-12541' do
  title 'The /etc/securetty file must have mode 0640 or less permissive.'
  desc 'The securetty file contains the list of terminals that permit direct root logins.  It must be protected from unauthorized modification.'
  desc 'check', 'Check /etc/securetty permissions.

Procedure:
# ls –lL /etc/securetty

If /etc/securetty has a mode more permissive than 0640, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/securetty file to 0640.

Procedure:
# chmod 0640 /etc/securetty'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8003r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12040'
  tag rid: 'SV-12541r2_rule'
  tag stig_id: 'GEN000000-LNX00660'
  tag gtitle: 'GEN000000-LNX00660'
  tag fix_id: 'F-11297r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
