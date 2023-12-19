control 'SV-80929' do
  title 'The Juniper Networks SRX Series Gateway IDPS must have only active Juniper Networks licenses.'
  desc 'If the IDP or UTM licenses are allowed to lapse, the Juniper SRX IDPS can still inspect traffic and continue to use the outdated signature database for rules, objects, and dynamic groups. However, updates to the signature database cannot be downloaded from Juniper Networks. This puts the network at risk since the updates are used to addresses new CERT and IAVM vulnerabilities.'
  desc 'check', "In operational mode, enter show system license.

If the license expiration for idp-sig and all other licenses installed are past today's date, this is a finding."
  desc 'fix', 'Update the expired licenses immediately following the procedures on the vendor website.'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG IDPS'
  tag check_id: 'C-67085r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66439'
  tag rid: 'SV-80929r1_rule'
  tag stig_id: 'JUSX-IP-000030'
  tag gtitle: 'SRG-NET-000512-IDPS-00194'
  tag fix_id: 'F-72515r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
