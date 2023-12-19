control 'SV-221255' do
  title 'The Exchange software baseline copy must exist.'
  desc 'Exchange software, as with other application software installed on a host system, must be included in a system baseline record and periodically reviewed; otherwise, unauthorized changes to the software may not be discovered. This effort is a vital step to securing the host and the applications, as it is the only method that may provide the ability to detect and recover from otherwise undetected changes, such as those that result from worm or bot intrusions. 

The Exchange software and configuration baseline is created and maintained for comparison during scanning efforts. Operational procedures must include baseline updates as part of configuration management tasks that change the software and configuration.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine the baseline documentation.  

Review the application software baseline procedures and implementation artifacts. 

Note the list of files and directories included in the baseline procedure for completeness. 

If an email software copy exists to serve as a baseline and is available for comparison during scanning efforts, this is not a finding.'
  desc 'fix', 'Implement an email software baseline process and update the EDSP.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22970r411891_chk'
  tag severity: 'medium'
  tag gid: 'V-221255'
  tag rid: 'SV-221255r612603_rule'
  tag stig_id: 'EX16-ED-000590'
  tag gtitle: 'SRG-APP-000380'
  tag fix_id: 'F-22959r411892_fix'
  tag 'documentable'
  tag legacy: ['SV-95301', 'V-80591']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
