control 'SV-207710' do
  title 'The Palo Alto Networks security platform must continuously monitor outbound communications traffic for unusual/unauthorized activities or conditions.'
  desc "If outbound communications traffic is not continuously monitored for unusual/unauthorized activities or conditions, there will be times when hostile activity may not be noticed and defended against.

Although some of the components in the site's content scanning solution may be used for periodic scanning assessment, the IDPS sensors and other components must provide continuous, 24 hours a day, 7 days a week monitoring.

Unusual/unauthorized activities or conditions related to information system outbound communications traffic include, for example, internal traffic that indicates the presence of malicious code within organizational information systems or propagating among system components, the unauthorized exporting of information, or signaling to external information systems. Anomalies within organizational information systems include, for example, large file transfers, long-time persistent connections, use of unusual protocols and ports, and communications with suspected or known malicious external entities."
  desc 'check', 'Obtain the network architecture diagrams and identify where traffic crosses from one internal zone to another and review the configuration of the Palo Alto Networks security platform.

If it does not filter traffic passing between zones, this is a finding.'
  desc 'fix', 'The network architecture diagrams must identify where traffic crosses from one internal zone to another.  The specific security policy is based on the authorized endpoints, applications, and protocols.

To create or edit a Security Policy:
Go to Policies >> Security
Select "Add" to create a new security policy or select the name of the security policy to edit it. 
Configure the specific parameters of the policy by completing the required information in the fields of each tab.
Commit changes by selecting "Commit" in the upper-right corner of the screen.  Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks IDPS'
  tag check_id: 'C-7964r358463_chk'
  tag severity: 'medium'
  tag gid: 'V-207710'
  tag rid: 'SV-207710r557390_rule'
  tag stig_id: 'PANW-IP-000050'
  tag gtitle: 'SRG-NET-000391-IDPS-00213'
  tag fix_id: 'F-7964r358464_fix'
  tag 'documentable'
  tag legacy: ['V-62691', 'SV-77181']
  tag cci: ['CCI-002662']
  tag nist: ['SI-4 (4) (b)']
end
