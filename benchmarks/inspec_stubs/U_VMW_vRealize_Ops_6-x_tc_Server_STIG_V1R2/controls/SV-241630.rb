control 'SV-241630' do
  title 'tc Server ALL log data and records must be backed up onto a different system or media.'
  desc 'Protection of tc Server ALL log data includes assuring log data is not accidentally lost or deleted. Backing up tc Server ALL log records to an unrelated system or onto separate media than the system the web server is actually running on helps to assure that, in the event of a catastrophic system failure, the log records will be retained.'
  desc 'check', 'Obtain supporting documentation from the ISSO.

Determine if log data and records are not being backed up onto a different system or media.

If log data and records are not being backed up onto a different system or media, this is a finding.'
  desc 'fix', 'Ensure log data and records are being backed up to a different system or separate media.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44906r683750_chk'
  tag severity: 'medium'
  tag gid: 'V-241630'
  tag rid: 'SV-241630r879582_rule'
  tag stig_id: 'VROM-TC-000315'
  tag gtitle: 'SRG-APP-000125-WSR-000071'
  tag fix_id: 'F-44865r683751_fix'
  tag 'documentable'
  tag legacy: ['SV-99545', 'V-88895']
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
