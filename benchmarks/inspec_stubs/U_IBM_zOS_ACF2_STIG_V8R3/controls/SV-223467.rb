control 'SV-223467' do
  title 'The EXITS GSO record value must specify the module names of site written ACF2 exit routines.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.'
  desc 'check', 'From the ACF Command enter:
SET CONTROL(GSO)
LIST LIKE(EXIT-)

If the GSO EXITS record values conform to the following requirements, this is not a finding.

Specifies the module names of site written ACF2 exit routines.

NOTE: The DSNPOST exit is optional and is not required to be specified in the GSO EXITS record. DSNPOST(module) SEVPRE(SEVPRE01) SEVPOST(SEVPST01)
NOTE: No other exits are authorized at this time.
NOTE: Local changes will be documented in writing with supporting documentation.

If there is any deviation from the above requirements in the GSO EXITS record values, this is a finding.'
  desc 'fix', 'Configure the EXITS GSO value to specify the module names of site written ACF2 exit routines.

Specifies the module names of site written ACF2 exit routines.

NOTE: The DSNPOST exit is optional and is not required to be specified in the GSO EXITS record.

DSNPOST(module) SEVPRE(SEVPRE01) SEVPOST(SEVPST01)

Example:
SET C(GSO)
INSERT EXITS DSNPOST(module) SEVPRE(SEVPRE01) SEVPOST(SEVPST01)

F ACF2,REFRESH(EXITS)

NOTE: No other exits are authorized at this time.

NOTE: Local changes will be justified in writing with supporting documentation.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25140r504519_chk'
  tag severity: 'medium'
  tag gid: 'V-223467'
  tag rid: 'SV-223467r533198_rule'
  tag stig_id: 'ACF2-ES-000490'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25128r504520_fix'
  tag 'documentable'
  tag legacy: ['V-97633', 'SV-106737']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
