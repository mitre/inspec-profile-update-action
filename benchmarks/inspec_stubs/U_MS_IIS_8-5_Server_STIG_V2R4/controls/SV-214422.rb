control 'SV-214422' do
  title 'The production IIS 8.5 web server must utilize SHA2 encryption for the Machine Key.'
  desc 'The Machine Key element of the ASP.NET web.config specifies the algorithm and keys that ASP.NET will use for encryption. The Machine Key feature can be managed to specify hashing and encryption settings for application services such as view state, forms authentication, membership and roles, and anonymous identification. Ensuring a strong encryption method can mitigate the risk of data tampering in crucial functional areas such as forms authentication cookies, or view state.'
  desc 'check', 'If .NET is not installed, this is Not Applicable.

Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Double-click the "Machine Key" icon in the website Home Pane.

Verify "HMACSHA256" or stronger encryption is selected for the Validation method and "Auto" is selected for the Encryption method.

If "HMACSHA256" or stronger encryption is not selected for the Validation method and/or "Auto" is not selected for the Encryption method, this is a finding.'
  desc 'fix', 'If .NET is not installed, this is Not Applicable.

Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Double-click the "Machine Key" icon in the web server Home Pane.

Set the Validation method to "HMACSHA256" or stronger.
Set the Encryption method to "Auto".

Click "Apply" in the "Actions" pane.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Server'
  tag check_id: 'C-15632r505360_chk'
  tag severity: 'medium'
  tag gid: 'V-214422'
  tag rid: 'SV-214422r508658_rule'
  tag stig_id: 'IISW-SV-000137'
  tag gtitle: 'SRG-APP-000231-WSR-000144'
  tag fix_id: 'F-15630r505361_fix'
  tag 'documentable'
  tag legacy: ['SV-91427', 'V-76731']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
