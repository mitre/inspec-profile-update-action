control 'SV-99545' do
  title 'tc Server ALL log data and records must be backed up onto a different system or media.'
  desc 'Protection of tc Server ALL log data includes assuring log data is not accidentally lost or deleted. Backing up tc Server ALL log records to an unrelated system or onto separate media than the system the web server is actually running on helps to assure that, in the event of a catastrophic system failure, the log records will be retained.'
  desc 'check', 'Obtain supporting documentation from the ISSO.

Determine if log data and records are not being backed up onto a different system or media.

If log data and records are not being backed up onto a different system or media, this is a finding.'
  desc 'fix', 'Ensure log data and records are being backed up to a different system or separate media.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x tcServer'
  tag check_id: 'C-88587r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88895'
  tag rid: 'SV-99545r1_rule'
  tag stig_id: 'VROM-TC-000315'
  tag gtitle: 'SRG-APP-000125-WSR-000071'
  tag fix_id: 'F-95637r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
