control 'SV-223513' do
  title 'ACF2 RESVOLS GSO record value must be set to Volmask(-). Any other setting requires documentation justifying the change.'
  desc 'The RESVOLS record defines DASD and mass storage volumes for which CA ACF2 is to provide protection at the data set name level.
Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive and tape drive, when used for backups) within an operating system.

This requirement addresses protection of user-generated data, as well as operating system-specific configuration data. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate, in accordance with the security category and/or classification of the information.'
  desc 'check', 'From an ACF command screen enter:
SET CONTROL(GSO)
LIST RESVOLS

If the GSO RESVOLS record values conform to the following requirements, this is not a finding.

VOLMASK() 

NOTE: Local changes will be documented in writing with supporting documentation. 

If there is any deviation from the above requirements in the GSO RESVOLS record values, this is a finding.'
  desc 'fix', 'Define the GSO RESVOLS record values to conform to the following requirements.

VOLMASK() 

Example:
SET C(GSO)
INSERT RESVOLS VOLMASK() 

F ACF2,REFRESH(SECVOLS)'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25186r695448_chk'
  tag severity: 'medium'
  tag gid: 'V-223513'
  tag rid: 'SV-223513r695449_rule'
  tag stig_id: 'ACF2-ES-000960'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag fix_id: 'F-25174r504610_fix'
  tag 'documentable'
  tag legacy: ['SV-106835', 'V-97731']
  tag cci: ['CCI-001199', 'CCI-000368']
  tag nist: ['SC-28', 'CM-6 c']
end
