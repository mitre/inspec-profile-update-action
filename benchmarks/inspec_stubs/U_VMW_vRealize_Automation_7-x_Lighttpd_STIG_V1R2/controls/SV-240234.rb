control 'SV-240234' do
  title 'Lighttpd log data and records must be backed up onto a different system or media.'
  desc 'Protection of Lighttpd log data includes assuring log data is not accidentally lost or deleted. Backing up Lighttpd log records to an unrelated system or onto separate media than the system the web server is actually running on helps to assure that, in the event of a catastrophic system failure, the log records will be retained.'
  desc 'check', 'Obtain supporting documentation from the ISSO.

Determine whether log data and records are being backed up to a different system or separate media.

If log data and records are not being backed up to a different system or separate media, this is a finding.'
  desc 'fix', 'Backup the log data and records to a different system or separate media.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43467r668005_chk'
  tag severity: 'medium'
  tag gid: 'V-240234'
  tag rid: 'SV-240234r879582_rule'
  tag stig_id: 'VRAU-LI-000140'
  tag gtitle: 'SRG-APP-000125-WSR-000071'
  tag fix_id: 'F-43426r667878_fix'
  tag 'documentable'
  tag legacy: ['SV-99901', 'V-89251']
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
