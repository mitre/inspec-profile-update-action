control 'SV-223954' do
  title 'The CA-TSS INACTIVE Control Option must be properly set.'
  desc 'Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.

Operating systems need to track periods of inactivity and disable application identifiers after 35 days of inactivity.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS MODIFY STATUS

If the INACTIVE Control Option is set to a value of "0", this is not a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to set the INACTIVE Control Option to a value of "0" days and proceed with the change.

The INACTIVE Control Option value is set properly with the command:

TSS MODIFY INACTIVE(0)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25627r516261_chk'
  tag severity: 'medium'
  tag gid: 'V-223954'
  tag rid: 'SV-223954r877795_rule'
  tag stig_id: 'TSS0-ES-000810'
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag fix_id: 'F-25615r516262_fix'
  tag 'documentable'
  tag legacy: ['SV-107719', 'V-98615']
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end
