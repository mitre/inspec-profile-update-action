control 'SV-79163' do
  title 'OHS content and configuration files must be part of a routine backup program.'
  desc 'Backing up web server data and web server application software after upgrades or maintenance ensures that recovery can be accomplished up to the current version.  It also provides a means to determine and recover from subsequent unauthorized changes to the software and data.

A tested and verifiable backup strategy will be implemented for web server software as well as all web server data files.  Backup and recovery procedures will be documented and the Web Manager or SA for the specific application will be responsible for the design, test, and implementation of the procedures.
 The site will have a contingency processing plan/disaster recovery plan that includes web servers. The contingency plan will be periodically tested in accordance with DoDI 8500.2 requirements.

The site will identify an off-site storage facility in accordance with DoDI 8500.2 requirements.  Off-site backups will be updated on a regular basis and the frequency will be documented in the contingency plan.'
  desc 'check', "1. Check that the following files and directories are backed up on a regular basis:

a) /etc/oraInst.loc
b) Directory identified by inventory_loc parameter within /etc/oraInst.loc
c) /etc/cap.ora
d) $MW_HOME

2. Confirm the ability to restore the above files and directories successfully.

3. Confirm the successful operation of OHS upon a successful restoration of the files and directories.

4. If the files aren't backed up on a regular schedule or the backups haven't been tested, this is a finding."
  desc 'fix', '1. Backup the following files on a regular basis:

a) /etc/oraInst.loc
b) Directory identified by inventory_loc parameter within /etc/oraInst.loc
c) /etc/cap.ora
d) $MW_HOME

2. Perform a restore and start the restored OHS server on a test machine.

3. Test the functionality of the restored OHS software on the test machine.'
  impact 0.3
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65415r1_chk'
  tag severity: 'low'
  tag gid: 'V-64673'
  tag rid: 'SV-79163r1_rule'
  tag stig_id: 'OH12-1X-000218'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-70603r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
