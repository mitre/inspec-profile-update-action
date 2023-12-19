control 'SV-223263' do
  title 'SharePoint must prevent non-privileged users from circumventing malicious code protection capabilities.'
  desc 'Malicious code protection software must be protected to prevent a non-privileged user or malicious piece of software from disabling the protection mechanism. A common tactic of malware is to identify the type of malicious code protection software running on the system and deactivate it. Malicious code includes viruses, worms, Trojan horses, and Spyware.

Examples include the capability for non-administrative users to turn off or otherwise disable anti-virus.'
  desc 'check', %q(Review the SharePoint server configuration to ensure non-privileged users are prevented from circumventing malicious code protection capabilities.

Confirm that the list of blocked file types configured in Central Administration matches the "blacklist" document in the application's SSP. See TechNet for default file types that are blocked: http://technet.microsoft.com/en-us/library/cc262496.aspx

Navigate to Central Administration.

Click "Manage web applications".

Select the web application by clicking its name.

Select "Blocked File Types" from the ribbon.

Compare the list of blocked file types to those listed in the SSP. If the SSP has file types that are not in the blocked file types list, this is a finding.

Repeat check for each web application.)
  desc 'fix', 'Configure the SharePoint server to prevent non-privileged users from circumventing malicious code protection capabilities.

Navigate to Central Administration.

Click "Manage web applications".

Select the web application by clicking its name.

Select "Blocked File Types" from the ribbon.

Add file types that are defined in the SSP but not in the list of blocked file types.

Click "Ok".

Repeat for each web application that has findings.'
  impact 0.7
  ref 'DPMS Target Microsoft SharePoint 2013'
  tag check_id: 'C-24936r430846_chk'
  tag severity: 'high'
  tag gid: 'V-223263'
  tag rid: 'SV-223263r612235_rule'
  tag stig_id: 'SP13-00-000140'
  tag gtitle: 'SRG-APP-000340'
  tag fix_id: 'F-24924r430847_fix'
  tag 'documentable'
  tag legacy: ['SV-74417', 'V-59987']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
