control 'SV-69581' do
  title 'The IDPS must provide log information in a format that can be extracted and used by centralized analysis tools.'
  desc 'Centralized review and analysis of log records from multiple IDPS components gives the organization the capability to better detect distributed attacks and provides increased data points for behavior analysis techniques. These techniques are invaluable in monitoring for indicators of complex attack patterns. 

To support the centralized analysis capability, the IDPS components must be able to provide the information in a format (e.g., Syslog) that can be extracted and used, allowing the application to effectively review and analyze the log records.'
  desc 'check', 'Verify the IDPS provides log information in a format that can be extracted and used by centralized analysis tools.

If the IDPS does not provide log information in a format that can be extracted and used by centralized analysis tools, this is a finding.'
  desc 'fix', 'Configure the IDPS to provide log information in a format that can be extracted and used by centralized analysis tools.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55957r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55335'
  tag rid: 'SV-69581r1_rule'
  tag stig_id: 'SRG-NET-000091-IDPS-00193'
  tag gtitle: 'SRG-NET-000091-IDPS-00193'
  tag fix_id: 'F-60201r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000154']
  tag nist: ['AU-6 (4)']
end
