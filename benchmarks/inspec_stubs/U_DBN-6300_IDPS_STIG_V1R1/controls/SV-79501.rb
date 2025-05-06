control 'SV-79501' do
  title 'To protect against unauthorized data mining, the DBN-6300 must detect code injection attacks launched against application objects including, at a minimum, application URLs and application code/input fields.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks that use unauthorized data mining techniques to attack applications may result in the compromise of information. 
 
Injection attacks allow an attacker to inject SQL code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database or change data on a website. 
 
IDPS component(s) with anomaly detection must be included in the IDPS implementation. These components must include behavior-based anomaly detection algorithms to monitor for atypical application behavior, which may include commands and accesses.'
  desc 'check', %q(View the organization's documentation to determine which databases are required to be protected. 
 
If the documentation does not exist, this is a finding. 
 
Navigate to Learning >> Time Regions and view the table of detected databases. 
 
For each database requiring protection, view the "State". Unprotected databases show a red shield. Protected databases show a green shield. 
 
If databases that are required to be protected are not being protected, this is a finding.)
  desc 'fix', %q(Configure a database for SQL injection protection.
 
Enable the SQL injection detection capabilities on the applicable interface for the database to be protected.
 
Navigate to Admin >> Capture >> Capture Sources.

Select the interface connected to the network that contains the database traffic.

Click on the "Enable" button and ensure the "Link up" indicator turns green.

Map the database.

Navigate to Database >> Database Mapping and find the database to be protected.

Click on the check box on the left.

Click on the first button at the top of the table which, when hovering over the button, is labeled "Map selected service to new db using their default names". 
The "Mapping Status" of the database will change to "Pending Mapping".

On the left side of the screen above the label that says "showing", click the button with the arrow. The "Mapping Status" for the database will change to "Mapped".
 
Note: The learning process requires enough database traffic to properly characterize normal application behavior. 
 
Navigate to Learning >> Time Regions and click on the left arrow to expand the window. 
 
Click on the plus sign to view the captured traffic. 
  
Organizations must capture a significant amount of traffic to enable the device to learn the traffic patterns. The vendor recommends at least three or more days of database traffic learning depending on the organization's traffic volume. 
 
Click the "Commit Learning" button on the lower right. 
 
View the "State" column of the database to verify the shield symbol is green.)
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 IDPS'
  tag check_id: 'C-65669r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65011'
  tag rid: 'SV-79501r1_rule'
  tag stig_id: 'DBNW-IP-000036'
  tag gtitle: 'SRG-NET-000319-IDPS-00185'
  tag fix_id: 'F-70951r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end
