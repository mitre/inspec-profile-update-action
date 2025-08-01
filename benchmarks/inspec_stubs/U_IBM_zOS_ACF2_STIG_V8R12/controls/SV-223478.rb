control 'SV-223478' do
  title 'CA-ACF2 database must be on a separate physical volume from its backup and recovery data sets.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.'
  desc 'check', 'From the ACF Command screen, enter:
SET CONTROL(GSO)
SHOW SYSTEMS

If the ACF2 database is not located on the same volume as either its alternate or backup file, this is not a finding.

If the ACF2 database is collocated with either its alternate or backup, this is a finding.'
  desc 'fix', 'Configure the placement of ACF2 files are on a separate volume from its backup and recovery data sets to provide backup and recovery in the event of physical damage to a volume.

Identify the ACF2 database(s), backup database(s), and recovery data set(s). Develop a plan to keep these data sets on different physical volumes. Implement the movement of these critical ACF2 files.

File location is an often overlooked factor in system integrity. It is important to ensure that the effects of hardware failures on system integrity and availability are minimized. Avoid collocation of files such as primary and alternate databases. For example, the loss of the physical volume containing the ACF2 database should not also cause the loss of the ACF2 backup database as a result of their collocation. Files that will be segregated from each other on separate physical volumes include, but are not limited to, the ACF2 database and its alternate or backup file.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25151r918607_chk'
  tag severity: 'medium'
  tag gid: 'V-223478'
  tag rid: 'SV-223478r918609_rule'
  tag stig_id: 'ACF2-ES-000600'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25139r918608_fix'
  tag 'documentable'
  tag legacy: ['V-97655', 'SV-106759']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
