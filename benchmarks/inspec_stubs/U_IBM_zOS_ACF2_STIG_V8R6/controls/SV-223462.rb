control 'SV-223462' do
  title 'The CA-ACF2 PSWD GSO record values for MAXTRY and PASSLMT must be properly set.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'From an ACF command screen enter:
SET CONTROL(GSO)
SHOW PSwdopts

If "MAXTRY" is set to "3", this is not a finding.

If "PASSLMT" is set to "3", this is not a finding.'
  desc 'fix', 'Configure the GSO option "MAXTRY" to equal "3".
Configure the GSO option "PASSLMT" to equal "3".'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25135r500518_chk'
  tag severity: 'medium'
  tag gid: 'V-223462'
  tag rid: 'SV-223462r533198_rule'
  tag stig_id: 'ACF2-ES-000430'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-25123r500519_fix'
  tag 'documentable'
  tag legacy: ['SV-106725', 'V-97621']
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
