control 'SV-91695' do
  title 'Applications used for nonlocal maintenance sessions must implement cryptographic mechanisms to protect the integrity of nonlocal maintenance and diagnostic communications.'
  desc 'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to manipulation, potentially allowing alteration and hijacking of maintenance sessions.'
  desc 'check', 'Verify SSL is configured to use SSL for the web management tool.

Navigate to Settings >> Initial Configuration >> Security.

If the check box for "Enforce secure communications (SSL) for user interface access" is not checked, this is a finding.'
  desc 'fix', 'Configure the User Interface (UI) web management tool to use HTTPS for communications.

Navigate to Settings >> Initial Configuration >> Security.

Select the check box for "Enforce secure communications (SSL) for user interface access".

Click on "Commit".'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76625r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76999'
  tag rid: 'SV-91695r1_rule'
  tag stig_id: 'DBNW-DM-000117'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-83695r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end
