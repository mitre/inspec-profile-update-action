control 'SV-218588' do
  title 'If the system is a Network Management System (NMS) server, it must only run the NMS and any software required by the NMS.'
  desc 'Installing extraneous software on a system designated as a dedicated Network Management System (NMS) server poses a security threat to the system and the network. Should an attacker gain access to the NMS through unauthorized software, the entire network may be susceptible to malicious activity.'
  desc 'check', 'Ask the SA if this is an NMS server. If it is an NMS server, then ask what other applications run on it. If there is anything other than network management software and DBMS software used only for the storage and inquiry of NMS data, this is a finding.'
  desc 'fix', 'Ensure only authorized software is loaded on a designated NMS server. Authorized software is limited to the NMS software itself, a database management system for the NMS server if necessary, and network management software.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20063r562816_chk'
  tag severity: 'medium'
  tag gid: 'V-218588'
  tag rid: 'SV-218588r603259_rule'
  tag stig_id: 'GEN005380'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-20061r562817_fix'
  tag 'documentable'
  tag legacy: ['V-4392', 'SV-63465']
  tag cci: ['CCI-000381', 'CCI-001208']
  tag nist: ['CM-7 a', 'SC-32']
end
