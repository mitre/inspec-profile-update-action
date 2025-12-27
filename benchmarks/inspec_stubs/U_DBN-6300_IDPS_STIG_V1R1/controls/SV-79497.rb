control 'SV-79497' do
  title 'To protect against unauthorized data mining, the DBN-6300 must monitor for and detect SQL injection attacks launched against data storage objects, including, at a minimum, databases, database records, and database fields.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks that use unauthorized data mining techniques to attack databases may result in the compromise of information.

The DBN-6300 is a passive listening device, and operates only as a detector, inspecting database traffic from a mirrored/SPAN port or tap for the purpose of analyzing every SQL statement visible on that network segment, and is therefore not in a position to block the flow of network traffic.  Any blocking will be performed by a different device on the network based on the analysis provided by the DBN-6300.  Protection against attacks launched against data storage objects, databases, database records and database fields will be managed by other devices, potentially based on information provided by the IDPS-6300.'
  desc 'check', %q(View the organization's documentation to determine which databases are required to be protected.
 
If the documentation does not exist, this is a finding.
 
Navigate to Learning >> Time Regions and view the table of detected databases.
 
For each database requiring protection, view the "State". Unprotected databases show a red shield. Protected databases show a green shield.
 
If databases that are required to be protected are not being protected, this is a finding.)
  desc 'fix', %q(Configure a database for SQL injection protection.
 
Enable the SQL injection detection capabilities on the applicable interface for the database to be protected.
 
Navigate to Admin >> Capture >> Capture Sources.
 
Select the interface connected to the network that contains the database traffic.
 
Click on the Enable button and ensure the Link up indicator turns green.
 
Map the database.
 
Navigate to Database >> Database Mapping and find the database to be protected.
 
Click on the check box on the left. 
 
Click on the first button at the top of the table which, when hovering over the button, is labeled "Map selected service to new db using their default names". The "Mapping Status" of the database will change to "Pending Mapping". 
 
On the left side of the screen above the label that says "showing", click the button with the arrow. The "Mapping Status" for the database will change to "Mapped".  
 
Note: The learning process requires enough database traffic to properly characterize normal application behavior. 
 
Navigate to Learning >> Time Regions and click on the left arrow to expand the window. 
 
Click on the plus sign to view the captured traffic. 
  
Organizations must capture a significant amount of traffic to enable the device to learn the traffic patterns. The vendor recommends at least three or more days of database traffic learning depending on the organization's traffic volume. 
 
Click the "Commit Learning" button on the lower right. 
 
View the "State" column of the database to verify the shield symbol is green.)
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 IDPS'
  tag check_id: 'C-65665r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65007'
  tag rid: 'SV-79497r1_rule'
  tag stig_id: 'DBNW-IP-000034'
  tag gtitle: 'SRG-NET-000318-IDPS-00183'
  tag fix_id: 'F-70947r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002346']
  tag nist: ['AC-23']
end
