control 'SV-237431' do
  title 'The Microsoft SCOM server must back up audit records at least every seven days onto a different system or system component than the system or component being audited.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. Regularly backing up audit records to a different system or onto separate media than the system being audited helps to assure, in the event of a catastrophic system failure, the audit records will be retained.'
  desc 'check', 'Determine if the security logs as well as the Operations Manager logs on the SCOM management server are being ingested by a tool such as Splunk, ArcSite, or Azure Log Analytics. 

If no effort is being made to retain log data on the SCOM server, this is a finding.'
  desc 'fix', 'Establish and implement a process for keeping the Security Log as well as the Operations Manager log. Most DoD enclaves are already running tools such as Splunk or Azure Log Analytics. It is important that these logs be ingested by these tools.'
  impact 0.5
  ref 'DPMS Target Microsoft SCOM'
  tag check_id: 'C-40650r643937_chk'
  tag severity: 'medium'
  tag gid: 'V-237431'
  tag rid: 'SV-237431r643939_rule'
  tag stig_id: 'SCOM-AU-000001'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag fix_id: 'F-40613r643938_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
