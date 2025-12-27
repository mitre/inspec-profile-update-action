control 'SV-79509' do
  title 'The DBN-6300 must integrate with a network-wide monitoring capability.'
  desc "An integrated, network-wide intrusion detection capability increases the ability to detect and prevent sophisticated distributed attacks based on access patterns and characteristics of access. 
 
Integration is more than centralized logging and a centralized management console. The enclave's monitoring capability may include multiple sensors, IPS, sensor event databases, behavior-based monitoring devices, application-level content inspection systems, malicious code protection software, scanning tools, audit record monitoring software, and network monitoring software. Some tools may monitor external traffic while others monitor internal traffic at key boundaries.  
 
These capabilities may be implemented using different devices and therefore can have different security policies and severity-level schema. This is valuable because content filtering, monitoring, and prevention can become a bottleneck on the network if not carefully configured."
  desc 'check', 'Verify integration with a network-wide monitoring capability. 
 
Obtain the IP address and port number for the centralized event management system (e.g., SIEM) from site personnel. 
  
Navigate to the "Admin" tab. 
  
Click on the "External Service Settings" button. 
  
Verify the IP address and port number for the centralized event management system are implemented.  
 
If the DBN-6300 is not configured to send syslog information to a centralized event management system that manages the DBN-6300 network-wide monitoring capability, this is a finding.'
  desc 'fix', 'Configure the DBN-6300 with syslog output to the SIEM. 
 
Navigate to the "Admin" tab.  
 
Click on the "External Service Settings" button. 
 
Enter the centralized event management system IP address and port number. 
 
Click on the "Commit" button to start the process.'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 IDPS'
  tag check_id: 'C-65677r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65019'
  tag rid: 'SV-79509r1_rule'
  tag stig_id: 'DBNW-IP-000046'
  tag gtitle: 'SRG-NET-000383-IDPS-00208'
  tag fix_id: 'F-70959r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002656']
  tag nist: ['SI-4 (1)']
end
