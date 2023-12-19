control 'SV-207688' do
  title 'The Palo Alto Networks security platform must enable Antivirus, Anti-spyware, and Vulnerability Protection for all authorized traffic.'
  desc 'The flow of all communications traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data.

Restricting the flow of communications traffic, also known as Information flow control, regulates where information is allowed to travel as opposed to who is allowed to access the information and without explicit regard to subsequent accesses to that information.

Traffic that is prohibited by the PPSM and Vulnerability Assessments must be denied by the policies configured in the Palo Alto Networks security platform; this is addressed in a separate requirement.  Traffic that is allowed by the PPSM and Vulnerability Assessments must still be inspected by the IDPS capabilities of the Palo Alto Networks security platform known as Content-ID.  Content-ID is enabled on a per rule basis using individual or group profiles to facilitate policy-based control over content traversing the network.'
  desc 'check', 'Review the list of authorized applications, endpoints, services, and protocols that has been added to the PPSM database.  Identify which traffic flows are authorized.

Go to  Objects >> Security Profiles >> Antivirus
If there are no Antivirus Profiles configured other than the default, this is a finding.

Go to Objects >> Security Profiles >> Anti-Spyware
View the configured Anti-Spyware Profiles.  If none are configured, this is a finding.

Go to Objects >> Security Profiles >> Vulnerability Protection
View the configured Vulnerability Protection Profiles.  If none are configured, this is a finding.

Review each of the configured security policies in turn.  For any Security Policy that allows traffic between Zones (interzone), view the "Profile" column.  If the "Profile" column does not display the Antivirus Profile, Anti-Spyware, and Vulnerability Protection symbols, this is a finding.'
  desc 'fix', 'Configure an Antivirus Profile, an Anti-spyware Profile, and a Vulnerability Protection Profile in turn.  Use these Profiles in the Security Policy or Policies that allows authorized traffic.
To create an Antivirus Profile:
Go to Objects >> Security Profiles >> Antivirus
Select "Add".
In the "Antivirus Profile" window,  complete the required fields.
Complete the "Name" and "Description" fields.
In the "Antivirus" tab, for all Decoders (SMTP, IMAP, POP3, FTP, HTTP, SMB protocols), set the Action to "drop" or "reset-both".
Select "OK".

To create a Vulnerability Protection Profile:
Go to Objects >> Security Profiles >> Vulnerability Protection
Select "Add".
In the "Vulnerability Protection Profile" window, complete the required fields.
In the "Name" field, enter the name of the Vulnerability Protection Profile.
In the "Description" field, enter the description of the Vulnerability Protection Profile.
In the "Rules" tab, select "Add".
In the "Vulnerability Protection Rule" window, 
In the "Rule Name" field, enter the Rule name,
In the "Threat Name" field, select "any",
In the "Action" field, select "drop" or "reset-both".
In the "Host type" field, select "any",
Select the checkboxes above the "CVE" and "Vendor ID" boxes. 
In the "Severity" section, select the "critical", "high", and "medium" check boxes.
Select "OK".

In the "Vulnerability Protection Profile" window, select the configured rule, then select "OK".
To configure an Anti-Spyware Profile:
Go to Objects >> Security Profiles >> Anti-Spyware
Select the name of a configured Anti-Spyware Profile or select "Add" to create a new one.
In the "Anti-Spyware Profile" window, complete the required fields in all tabs.
In the "Rules" tab, select the name of a configured Anti-Spyware Rule or select "Add" to create a new one.
Complete the required fields.
For the Category field, select "any".
For the Action field, select "Drop" or "reset-both".
For the Severity field, select "All" or configured multiple rules, one for each Severity.
Select "OK". 
Select "OK" again.

Go to Policies >> Security
Select an existing policy rule or select "Add" to create a new one.
In the "Actions" tab in the "Profile Setting" section; in the "Profile Type" field, select "Profiles".  The window will change to display the different categories of Profiles.  
In the "Actions" tab in the "Profile Setting" section; in the "Antivirus" field, select the configured Antivirus Profile.
In the "Actions" tab in the "Profile Setting" section; in the "Anti-spyware" field, select the configured or "Strict Anti-spyware" Profile.
In the "Actions" tab in the "Profile Setting" section; in the "Vulnerability Protection" field, select the configured Vulnerability Protection Profile.
Commit changes by selecting "Commit" in the upper-right corner of the screen.  Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks IDPS'
  tag check_id: 'C-7942r358397_chk'
  tag severity: 'medium'
  tag gid: 'V-207688'
  tag rid: 'SV-207688r557390_rule'
  tag stig_id: 'PANW-IP-000001'
  tag gtitle: 'SRG-NET-000018-IDPS-00018'
  tag fix_id: 'F-7942r358398_fix'
  tag 'documentable'
  tag legacy: ['SV-77137', 'V-62647']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
