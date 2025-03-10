control 'SV-220355' do
  title 'MarkLogic Server must limit privileges to change software modules, including stored procedures, functions, and triggers, and links to software external to the DBMS.'
  desc 'If the system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', 'Review monitoring procedures and implementation evidence to verify monitoring of changes to MarkLogic software libraries, related applications, and configuration files is done.

If a third-party file automated tool is used, this is not a finding.

To check for automated monitoring, issue the following command at a command prompt with a user that has administrative privileges:

Check to see if the crond service is running for scheduling recurring tasks. 

If it is not running, this is a finding.
> sudo systemctl status crond

Check to see if ml-filechange-mon.sh is in the cron schedule, and runs frequently enough to meet System Security Plan (SSP) requirements. If the script is not scheduled to run, or does not run frequently enough to meet the SSP requirements, this is a finding.
> sudo crontab -l | grep ml-filechange

Check ml-filechange-mon.sh to verify email addresses have been configured to receive alerts. If no email addresses have been added, this is a finding.
> grep "EMAIL_LIST" /path/to/ml-filechange-mon.sh'
  desc 'fix', 'Implement procedures to monitor for unauthorized changes to DBMS software libraries, related software application libraries, and configuration files. If a third-party automated tool is not employed, an automated job that reports file information on the directories and files of interest and compares them to the baseline report for the same will meet the requirement. 

The supplemental file "ml-filechange-mon.sh" can be used to meet this requirement. 
- Edit the ml-filechange-mon.sh script with the correct email addresses and notification level.
- Place the script in a location that can be accessed by the cron daemon.
- Edit the crontab, and configure the script to run frequently enough to meet DoD minimum requirements.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22070r401516_chk'
  tag severity: 'medium'
  tag gid: 'V-220355'
  tag rid: 'SV-220355r622777_rule'
  tag stig_id: 'ML09-00-002500'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag fix_id: 'F-22059r401517_fix'
  tag 'documentable'
  tag legacy: ['SV-110057', 'V-100953']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
