control 'SV-6428' do
  title 'An appropriate backup strategy does not exist for the data.'
  desc 'Data integrity and availability are key security objectives.  Adequate data backup is one strategy that is crucial to meeting these objectives.  Although users of desktop applications may not be creating mission critical data, all their data represents a resource that, if lost, could result in a permanent loss of information or productivity.

A backup strategy is highly dependent on the physical and logical environments.  In environments where users frequently operate disconnected from a LAN, as in the case of notebook PC users who travel, it is not generally practical for the users to store all their data on a file server.  Developers may require standalone copies of program code while additions or alterations are in progress.  For these and other reasons, strict requirements for desktop backup are not addressed in this document.  However, this section does provide recommendations that should be considered.

Users should make conscious decisions about the physical location where desktop application data is stored.  They should be aware of the backup policy for that location.  Any backup policy should be implemented in accordance with the following:

-	Mission critical data should be stored on file servers with a formal data backup policy.  Storage of mission critical data on desktop machines should be considered temporary.

-	To the greatest extent possible, data files should be stored in a directory hierarchy that is separate from program files.

-	An incremental, or change-based, backup solution can be used daily.

-	A full data backup solution should be used at least weekly.

-	Use of a Compact Disk-Recordable (CD-R) or Compact Disk-ReWritable (CD-RW) drive should be considered for desktop machines.  CD-R and CD-RW disks provide high capacity at relatively low cost.

-	The backup data should be stored on media or another machine that is not physically close to the original data source.

-	Backup media should receive proper care according to its characteristics.  Regular rotation of tape media is necessary to ensure usability.  The media should be clearly labeled, including any appropriate security classification marking.

-	Backup tools and schedules should be documented.

-	Restoration tools and methods should be documented and they should be tested via restoration at least annually.'
  desc 'check', 'Procedure:  Interview the SA to determine the type of data being housed on the machine.  Interview the SA to determine the backup process being used for the data.  

Criteria:  If there is no backup process or the backup process is inadequate for the data on the machine, this is a finding.'
  desc 'fix', 'Interview the SA to determine the type of data on the machine and its backup process.  If there is no backup process or the process is inadequate, have the SA create a new backup process.'
  impact 0.5
  ref 'DPMS Target Desktop Application - General'
  tag check_id: 'C-1035r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6355'
  tag rid: 'SV-6428r1_rule'
  tag stig_id: 'DTGW001'
  tag gtitle: 'DTGW001-Appropriate backup strategy does not exist'
  tag fix_id: 'F-5881r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
