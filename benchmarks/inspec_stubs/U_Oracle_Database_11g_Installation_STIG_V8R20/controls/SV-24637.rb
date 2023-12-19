control 'SV-24637' do
  title 'DBMS backup and restoration files should be protected from unauthorized access.'
  desc 'Lost or compromised DBMS backup and restoration files may lead to not only the loss of data, but also the unauthorized access to sensitive data. Backup files need the same protections against unauthorized access when stored on backup media as when online and actively in use by the database system. In addition, the backup media needs to be protected against physical loss. Most DBMSs maintain online copies of critical control files to provide transparent or easy recovery from hard disk loss or other interruptions to database operation.'
  desc 'check', 'Review documented backup and restoration procedures to determine ownership and access during all phases of backup and recovery.

Review file protections assigned to online backup and restoration files and tools.

Review access, physical security protections and documented procedures for offline backup and restoration files and tools.

If implementation evidence indicates that backup or restoration files are subject to corruption, unauthorized access or physical loss, this is a Finding.'
  desc 'fix', 'Develop, document and implement protection for backup and restoration files.

Document personnel and the level of access authorized for each to backup and restoration files and tools.

In addition to physical and host system protections, consider other methods including password protection of the files.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29161r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15120'
  tag rid: 'SV-24637r1_rule'
  tag stig_id: 'DG0064-ORACLE11'
  tag gtitle: 'DBMS backup and restoration file protection'
  tag fix_id: 'F-26173r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
