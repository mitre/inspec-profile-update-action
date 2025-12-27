control 'SV-55772' do
  title 'An ISDN-based VTC system supporting secure (classified) and non-secure (unclassified) conferences while implementing dialing capability from the CODEC must utilize an approved EIA-366-A dial isolator that disconnects the dialing channel between the CODEC and IMUX when the IMUX signals it is connected to another IMUX (i.e., the session is connected).'
  desc 'When dialing is performed from the CODEC, an EIA-366 connection is made between the CODEC and the IMUX to carry the dialing instructions to the IMUX which actually performs the dialing function. 

This is not an issue if there is no EIA-366-A connection between the CODEC and the IMUX and all dialing is performed from the IMUX.'
  desc 'check', 'Review the documentation to determine whether an approved EIA-366-A dial isolator is in place. DISN Video Services (DVS) maintains a list of A/B switches and dial isolators that have been TEMPEST certified to meet the above requirements at http://disa.mil/Services/Network-Services/Video/~/media/Files/DISA/Services/DVS/red_black_peripherals.xls. If a dial isolator is not implemented and used, or the dial isolator is not on the list, this is a finding.

If there is no EIA-366-A connection between the CODEC and the IMUX and all dialing is performed from the IMUX, this is not a finding.'
  desc 'fix', 'Obtain and install an approved EIA-366-A dial isolator unless there is no EIA-366-A connection between the CODEC and the IMUX and all dialing is performed from the IMUX.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-49191r7_chk'
  tag severity: 'medium'
  tag gid: 'V-43043'
  tag rid: 'SV-55772r1_rule'
  tag stig_id: 'RTS-VTC 7380'
  tag gtitle: 'RTS-VTC 7380 [ISDN]'
  tag fix_id: 'F-48623r2_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECSC-1, ECTC-1'
end
