control 'SV-12481' do
  title 'The system must log successful and unsuccessful access to the root account.'
  desc 'If successful and unsuccessful logins and logouts are not monitored or recorded, access attempts cannot be tracked.  Without this logging, it may be impossible to track unauthorized access to the system.'
  desc 'check', 'Verify the system logs successful and unsuccessful access to the root account.  If it does not, this is a finding.'
  desc 'fix', 'Troubleshoot the system logging configuration to provide for logging of root account login attempts.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-7945r2_chk'
  tag severity: 'medium'
  tag gid: 'V-11980'
  tag rid: 'SV-12481r2_rule'
  tag stig_id: 'GEN001060'
  tag gtitle: 'GEN001060'
  tag fix_id: 'F-11241r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
