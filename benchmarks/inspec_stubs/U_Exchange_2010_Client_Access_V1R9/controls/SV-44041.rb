control 'SV-44041' do
  title 'Exchange software baseline copy must exist.'
  desc 'Exchange software, as with other application software installed on a host system, must be included in a system baseline record and periodically reviewed;  otherwise unauthorized changes to the software may not be discovered. This effort is a vital step to securing the host and the applications, as it is the only method that may provide the ability to detect and recover from otherwise undetected changes, such as those that result from worm or bot intrusions. 

The Exchange software and configuration baseline is created and maintained for comparison during scanning efforts. Operational procedures must include baseline updates as part of configuration management tasks that change the software and configuration.'
  desc 'check', 'Access the EDSP and locate the baseline documentation.  

Review the application software baseline procedures and implementation artifacts. Note the list of files and directories included in the baseline procedure for completeness. 

If an email software copy exists to serve as a baseline and is available for comparison during scanning efforts, this is not a finding.'
  desc 'fix', 'Implement email software baseline process. Document the details in the EDSP.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41728r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33621'
  tag rid: 'SV-44041r1_rule'
  tag stig_id: 'Exch-3-006'
  tag gtitle: 'Exch-3-006'
  tag fix_id: 'F-37513r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
