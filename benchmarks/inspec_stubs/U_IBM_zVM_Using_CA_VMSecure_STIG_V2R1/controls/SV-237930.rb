control 'SV-237930' do
  title 'The IBM z/VM JOURNALING statement must be coded on the configuration file.'
  desc 'If auditing is enabled late in the start-up process, the actions of some start-up processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.'
  desc 'check', 'Examine the Product configuration file.

If the “JOURNALING” statement does not specify “ON”, this is a finding.'
  desc 'fix', 'Configure the system configuration “JOURNALING” statement to “JOURNALING ON”.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41140r649628_chk'
  tag severity: 'medium'
  tag gid: 'V-237930'
  tag rid: 'SV-237930r649630_rule'
  tag stig_id: 'IBMZ-VM-000810'
  tag gtitle: 'SRG-OS-000254-GPOS-00095'
  tag fix_id: 'F-41099r649629_fix'
  tag 'documentable'
  tag legacy: ['SV-93613', 'V-78907']
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
