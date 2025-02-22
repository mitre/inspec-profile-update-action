control 'SV-79515' do
  title 'When implemented for protection of the database tier, the DBN-6300 must be logically connected for maximum database traffic visibility.'
  desc %q(Configuring the IDPS to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements. 
 
Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the network element. Security-related parameters are those parameters impacting the security state of the network element, including the parameters required to satisfy other security control requirements. For the network element, security-related parameters include settings for communications traffic management configurations. If the DBN-6300 is installed incorrectly in the site's network architecture, vulnerable databases may not be detected and consequently may remain unprotected. 
 
To ensure optimum protection, the DBN-6300 must be logically installed between the application and database tiers of the network. The device has multiple interfaces that allow several connections to accommodate various network architectures. The device is installed as a passive listening device on all applicable subnetworks using the available ports. When placed correctly, the device monitors the "last mile" prior to database access, which is where SQL is optimally monitored.)
  desc 'check', "Ask the site representative if the DBN-6300 is used to protect the database tier. 
 
If the DBN-6300 is not used to protect the database tier, this is not a finding.  
 
Ask the site for documentation of which database tier is required to be protected. 
 
Verify connectivity of the capture ports to the correct database tier that is required to be protected. 
 
If the DBN-6300 is not connected to protect the database tier for maximum database traffic visibility of the organization's databases, this is a finding."
  desc 'fix', 'Evaluate the site architecture to determine where the optimum logical connections would provide maximum database visibility. 
 
Disconnect the network taps from the incorrectly attached network ports. Reconnect the correctly identified taps. 
 
Navigate to the Admin >> Capture >> Port Configuration menu. 
 
Click on "Port Enabled", if it is not already enabled, to ensure that the DBN-6300 will see and capture traffic. 
 
Navigate to the "Database" tab and choose "Service Discovery". 
 
Verify that database services are beginning to appear on the page.'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 IDPS'
  tag check_id: 'C-65683r3_chk'
  tag severity: 'medium'
  tag gid: 'V-65025'
  tag rid: 'SV-79515r1_rule'
  tag stig_id: 'DBNW-IP-000060'
  tag gtitle: 'SRG-NET-000512-IDPS-00194'
  tag fix_id: 'F-70965r5_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
