control 'SV-75241' do
  title 'The Google Search Appliances must respond to security function anomalies by notifying the system administrator.'
  desc 'The need to verify security functionality applies to all security functions. 

For those security functions not able to execute automated self-tests the organization either implements compensating security controls or explicitly accepts the risk of not performing the verification as required. Information system transitional states include startup, restart, shutdown, and abort.'
  desc 'check', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.

Navigate to "Administration", select "Network Settings".

Ensure that a valid Syslog server is entered correctly.

If events are sent and recorded on the Syslog server, this is not a finding.'
  desc 'fix', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.
  
Navigate to "Administration", select "Network Settings".

Enter a valid Syslog server.

Ensure that events are sent and recorded on the Syslog server.'
  impact 0.5
  ref 'DPMS Target Google Search Appliance v3.1'
  tag check_id: 'C-61713r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60789'
  tag rid: 'SV-75241r1_rule'
  tag stig_id: 'GSAP-00-000660'
  tag gtitle: 'SRG-APP-000200'
  tag fix_id: 'F-66471r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001674']
  tag nist: ['SI-6']
end
