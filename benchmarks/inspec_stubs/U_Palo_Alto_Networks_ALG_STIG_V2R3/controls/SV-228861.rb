control 'SV-228861' do
  title 'The Palo Alto Networks security platform must use a Vulnerability Protection Profile that blocks any critical, high, or medium threats.'
  desc 'If the network does not provide safeguards against DoS attacks, network resources may be unavailable to users. 

Installation of content filtering gateways and application-layer firewalls at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume, type, or protocol usage.'
  desc 'check', 'Go to Objects >> Security Profiles >> Vulnerability Protection
If there are no Vulnerability Protection Profiles configured, this is a finding.

Ask the Administrator which Vulnerability Protection Profile is used for interzone traffic.
View the configured Vulnerability Protection Profiles.
Check the "Severity" and "Action" columns.
If the Vulnerability Protection Profile used for interzone traffic does not block all critical, high, and medium threats, this is a finding.

Go to Policies >> Security
Review each of the configured security policies in turn.
For any Security Policy that affects traffic between Zones (interzone), view the "Profile" column.
If the "Profile" column does not display the  "Vulnerability Protection Profile" symbol, this is a finding.'
  desc 'fix', 'To add a Vulnerability Protection Profile:
Go to Objects >> Security Profiles >> Vulnerability Protection
Select "Add".
In the "Vulnerability Protection Profile" window, complete the required fields.
In the "Name" field, enter the name of the Vulnerability Protection Profile.
In the "Description" field, enter the description of the Vulnerability Protection Profile.
In the "Rules" tab, select "Add".
In the "Vulnerability Protection Rule" window, 
In the "Rule Name" field, enter the Rule name,
In the "Threat Name" field, enter "any" (this will match all signatures),
In the "Action" field, select "block".
In the "Host type" field, select "any",
Select the checkboxes above the "CVE" and "Vendor ID" boxes. 
In the "Severity" section, select the "critical", "high", and "medium" check boxes.
Select "OK".

In the "Vulnerability Protection Profile" window, select the configured rule, then select "OK".
Use the Profile in a Security Policy:
Go to Policies >> Security
Select an existing policy rule or select "Add" to create a new one.
In the "Actions" tab in the "Profile Setting" section; in the "Profile Type" field, select "Profiles".  The window will change to display the different categories of Profiles.  
In the "Actions" tab in the "Profile Setting" section; in the "Vulnerability Protection" field, select the configured Vulnerability Protection Profile.
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31096r513878_chk'
  tag severity: 'medium'
  tag gid: 'V-228861'
  tag rid: 'SV-228861r831603_rule'
  tag stig_id: 'PANW-AG-000105'
  tag gtitle: 'SRG-NET-000362-ALG-000126'
  tag fix_id: 'F-31073r513879_fix'
  tag 'documentable'
  tag legacy: ['SV-77093', 'V-62603']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
