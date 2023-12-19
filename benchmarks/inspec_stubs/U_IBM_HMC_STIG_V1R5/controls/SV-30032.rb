control 'SV-30032' do
  title 'Hardware Management Console audit record content data must be backed up.'
  desc 'The Hardware Management Console has the ability to backup and display the following data: 1) Critical console data 2) Critical hard disk information 3) Backup of critical CPC data and 4) Security Logs. Failure to backup and archive the listed data could make auditing of system incidents and history unavailable and could impact recovery for failed components.'
  desc 'check', 'Have the System Administrator produce a log by date validating that backups are being performed for Security logs and Critical console data on a routine scheduled basis (e.g., daily, weekly, monthly, quarterly, annually) and copies are rotated to off site storage. Compare the list of backups made to a physical inventory of storage media to verify that HMC backups are being retained as expected. If backups are either not being made, or there are obvious gaps in storage and retention of the backups, this is a finding.'
  desc 'fix', 'The System Administrator will see that a log exists to verify that backups are being performed. This list will have the date and reason for the backup.

Backup security logs. This task will archive a security log for the console. 

The backup critical console data backs up the data that is stored on your Hardware Management Console hard disk and is critical to support Hardware Management Console operations. You should back up the Hardware Management Console data after changes have been made to the Hardware Management Console or to the information associated with the processor cluster. Information associated with processor cluster changes is usually information that you are able to modify or add to the Hardware Management Console hard disk. Association of an activation profile to an object, the definition of a group, hardware configuration data, and receiving internal code changes are examples of modifying and adding information, respectively. Use this task after customizing your processor cluster in any way. A backup copy of hard disk information may be restored to your Hardware Management Console following the repair or replacement of the fixed disk.'
  impact 0.5
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-29885r6_chk'
  tag severity: 'medium'
  tag gid: 'V-24364'
  tag rid: 'SV-30032r4_rule'
  tag stig_id: 'HMC0180'
  tag gtitle: 'HMC0180'
  tag fix_id: 'F-26781r3_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Systems Programmer']
  tag ia_controls: 'COSW-1, ECTB-1'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
