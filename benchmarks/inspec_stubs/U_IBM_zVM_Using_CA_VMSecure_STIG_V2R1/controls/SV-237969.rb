control 'SV-237969' do
  title 'IBM z/VM system administrator must develop procedures to manually control temporary, interactive, and emergency accounts.'
  desc 'Proper handling of temporary, inactive, and emergency accounts require automatic notification and action rather than at the convenience of the systems administrator. However in the absence of automated process manual procedures must be in place to assure that possible sensitive accounts are not compromised.'
  desc 'check', 'Ask the system administrator (SA) for documented manual procedures to handle temporary, inactive, and emergency accounts.

If there are no procedures or they are not documented and filed with the ISSM/ISSO, this is a finding.'
  desc 'fix', 'Develop a manual procedure to handle temporary, inactive, and emergency accounts in accordance with appropriate policies.

Ensure that the procedures are documented and filed with ISSM/ISSO.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41179r649745_chk'
  tag severity: 'medium'
  tag gid: 'V-237969'
  tag rid: 'SV-237969r649747_rule'
  tag stig_id: 'IBMZ-VM-002390'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-41138r649746_fix'
  tag 'documentable'
  tag legacy: ['SV-93691', 'V-78985']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
