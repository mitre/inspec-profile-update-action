control 'SV-240933' do
  title 'The vAMI log records must be backed up at least every seven days onto a different system or system component than the system or component being logged.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. Backing up log records to a different system or onto separate media from the system that the vAMI is actually running on helps to assure that in the event of a catastrophic system failure, the log records will be retained.'
  desc 'check', 'Interview the ISSO and/or the SA. 

Determine if there is a local procedure to back up log records at least every seven days onto a different system. 

If a procedure does not exist or is not being followed, this is a finding.'
  desc 'fix', 'Develop and implement a site procedure to back up the log data and records to a different system or separate media at least every seven days.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x vAMI'
  tag check_id: 'C-44166r675964_chk'
  tag severity: 'medium'
  tag gid: 'V-240933'
  tag rid: 'SV-240933r879582_rule'
  tag stig_id: 'VRAU-VA-000160'
  tag gtitle: 'SRG-APP-000125-AS-000084'
  tag fix_id: 'F-44125r675965_fix'
  tag 'documentable'
  tag legacy: ['SV-100859', 'V-90209']
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
