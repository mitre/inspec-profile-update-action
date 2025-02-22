control 'SV-223475' do
  title 'CA-ACF2 RULEOPTS GSO record values must be set to the values specified.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.'
  desc 'check', 'From the ACF Command enter:
SET CONTROL(GSO)
LIST RULEOPTS

If the following options are defined, this is not a finding.

NO$NOSORT 
CENTRAL
CHANGE
DECOMP(AUDIT SECURITY) | DECOMP(AUDIT) | DECOMP(SECURITY)

The other RULEOPTS values should be assigned carefully as they affect the Rules and Infostorage databases.'
  desc 'fix', 'Configure the GSO RULEOPTS record values to conform to the following requirements.

NO$NOSORT 
CENTRAL
CHANGE
DECOMP(AUDIT SECURITY) | DECOMP(AUDIT) | DECOMP(SECURITY)

The other RULEOPTS values should be assigned carefully as they affect the Rules and Infostorage databases.

Example:
SET C(GSO)
INSERT RULEOPTS NO$NOSORT CENTRAL CHANGE NOCOMPDYN DECOMP(AUDIT SECURITY)  
F ACF2,REFRESH(RULEOPTS)'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25148r695414_chk'
  tag severity: 'medium'
  tag gid: 'V-223475'
  tag rid: 'SV-223475r695416_rule'
  tag stig_id: 'ACF2-ES-000570'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25136r695415_fix'
  tag 'documentable'
  tag legacy: ['V-97649', 'SV-106753']
  tag cci: ['CCI-000366', 'CCI-000368']
  tag nist: ['CM-6 b', 'CM-6 c']
end
