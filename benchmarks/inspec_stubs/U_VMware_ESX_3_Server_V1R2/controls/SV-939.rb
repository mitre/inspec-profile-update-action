control 'SV-939' do
  title 'A system vulnerability tool must be run on the system monthly.'
  desc 'A system vulnerability tool compares file and directory integrity to the baseline. It can alert the system administrator to unauthorized changes in files or directories. Unauthorized changes in files and directories can give a user unauthorized access to system resources.'
  desc 'check', 'Perform the following to check for a security tool executing monthly:

	#	crontab –l 

Check for the existence of a vulnerability assessment tool being scheduled and run monthly.  If no entries exist in the crontab, ask the SA if a vulnerability tool is run monthly.  In addition, if the tool is run monthly, ask to see any reports that may have been generated from the tool.  If a tool is not run monthly then this a finding.'
  desc 'fix', 'Add a monthly cronjob to run the system vulnerability tool.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-886r2_chk'
  tag severity: 'medium'
  tag gid: 'V-939'
  tag rid: 'SV-939r2_rule'
  tag stig_id: 'GEN006540'
  tag gtitle: 'GEN006540'
  tag fix_id: 'F-1093r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'VIVM-1'
end
