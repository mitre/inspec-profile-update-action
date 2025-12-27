control 'SV-223512' do
  title 'ACF2 SECVOLS GSO record value must be set to VOLMASK(). Any local changes are justified and documented with the ISSO.'
  desc 'The SECVOLS record defines the DASD and tape volumes for which CA-ACF2 provides volume-level protection. Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive and tape drive, when used for backups) within an operating system.

This requirement addresses protection of user-generated data, as well as operating system-specific configuration data. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate, in accordance with the security category and/or classification of the information.'
  desc 'check', 'From an ACF command screen enter:
SET CONTROL(GSO)
LIST SECVOLS

If the GSO SECVOLS record values conform to the following requirements, this is not a finding.

VOLMASK() 

NOTE: Local changes will be documented in writing with supporting documentation. 

If there is any deviation from the above requirements in the GSO SECVOLS record values, this is a finding.'
  desc 'fix', 'Define the GSO SECVOLS record values to conform to the following requirements.

VOLMASK() 

Example:
SET C(GSO)
INSERT SECVOLS VOLMASK() 

F ACF2,REFRESH(SECVOLS)'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25185r695446_chk'
  tag severity: 'medium'
  tag gid: 'V-223512'
  tag rid: 'SV-223512r695447_rule'
  tag stig_id: 'ACF2-ES-000950'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag fix_id: 'F-25173r504607_fix'
  tag 'documentable'
  tag legacy: ['V-97727', 'SV-106831']
  tag cci: ['CCI-000368', 'CCI-001199']
  tag nist: ['CM-6 c', 'SC-28']
end
