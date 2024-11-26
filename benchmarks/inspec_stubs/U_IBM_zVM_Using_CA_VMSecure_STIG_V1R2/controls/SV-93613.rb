control 'SV-93613' do
  title 'The IBM z/VM JOURNALING statement must be coded on the configuration file.'
  desc 'If auditing is enabled late in the start-up process, the actions of some start-up processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.'
  desc 'check', 'Examine the Product configuration file.

If the “JOURNALING” statement does not specify “ON”, this is a finding.'
  desc 'fix', 'Configure the system configuration “JOURNALING” statement to “JOURNALING ON”.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78493r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78907'
  tag rid: 'SV-93613r1_rule'
  tag stig_id: 'IBMZ-VM-000810'
  tag gtitle: 'SRG-OS-000254-GPOS-00095'
  tag fix_id: 'F-85657r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
