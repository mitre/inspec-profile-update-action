control 'SV-79511' do
  title 'The DBN-6300 must continuously monitor inbound communications traffic between the application tier and the database tier for unusual/unauthorized activities or conditions at the SQL level.'
  desc "If inbound communications traffic is not continuously monitored for unusual/unauthorized activities or conditions, there will be times when hostile activity may not be noticed and defended against. 
 
Although some of the components in the site's content scanning solution may be used for periodic scanning assessment, the IDPS sensors and other components must provide continuous, 24 hours a day, 7 days a week monitoring. 
 
Unusual/unauthorized activities or conditions related to information system inbound communications traffic include, for example, internal traffic that indicates the presence of malicious code within organizational information systems or propagating among system components, the unauthorized exporting of information, or signaling to external information systems. Anomalies within organizational information systems include, for example, large file transfers, long-time persistent connections, use of unusual protocols and ports, and communications with suspected or known malicious external entities."
  desc 'check', %q(View the organization's documentation to determine which databases are required to be protected. 
 
Ask the site representative if the device is used continuously or if periodic monitoring is performed. 
 
Navigate to Learning >> Time Regions and view the table of detected databases. 
 
For each database requiring protection, view the "State". Unprotected databases show a red shield. Protected databases show a green shield. 
 
If continuous monitoring is not performed by the organization, this is a finding.)
  desc 'fix', 'Configure the DBN-6300 with syslog output to the SIEM.  

Navigate to the "Admin" tab. 

Click on "External Service Settings" button.

Enter the centralized event management system IP address and port number.

Click on the "Commit" button to start the process. 

Configure a database for SQL injection protection for continuous protection.

Enable the SQL injection detection capabilities on the applicable interface for the database to be protected.

Navigate to Admin >> Capture >> Capture Sources.

Select the interface connected the network that contains the database traffic.

Click on the "Enable" button and ensure the Link up indicator turns green.'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 IDPS'
  tag check_id: 'C-65679r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65021'
  tag rid: 'SV-79511r1_rule'
  tag stig_id: 'DBNW-IP-000050'
  tag gtitle: 'SRG-NET-000390-IDPS-00212'
  tag fix_id: 'F-70961r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002661']
  tag nist: ['SI-4 (4) (b)']
end
