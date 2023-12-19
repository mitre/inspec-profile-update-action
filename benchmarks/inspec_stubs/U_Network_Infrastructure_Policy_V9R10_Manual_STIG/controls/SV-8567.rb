control 'SV-8567' do
  title 'The organization must ensure all switches and associated cross-connect hardware are kept in a secure Intermediate Distribution Frame (IDF) or an enclosed cabinet that is kept locked.'
  desc 'Since the IDF includes all hardware required to connect horizontal wiring to the backbone, it is imperative that all switches and associated cross-connect hardware are kept in a secured IDF or an enclosed cabinet that is kept locked. This will also prevent an attacker from gaining privilege mode access to the switch. Several switch products only require a reboot of the switch in order to reset or recover the password.'
  desc 'check', 'Inspect switches and associated cross-connect hardware are kept in a secured IDF.  If the hardware is located in an open area, verify all hardware is located in a secured and locked cabinet.

If switches and associated cross-connect hardware are not kept in secured IDFs or locked cabinet, this is a finding.'
  desc 'fix', 'Place switches and associated cross-connect hardware in a secured IDF.  If the hardware is located in an open area, ensure the hardware is located in a secured and locked cabinet.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-7462r5_chk'
  tag severity: 'medium'
  tag gid: 'V-8081'
  tag rid: 'SV-8567r3_rule'
  tag stig_id: 'NET-VLAN-001'
  tag gtitle: 'NET-VLAN-001 Switches  cross-connects are not in secure IDF or locked cabinet'
  tag fix_id: 'F-7656r4_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
