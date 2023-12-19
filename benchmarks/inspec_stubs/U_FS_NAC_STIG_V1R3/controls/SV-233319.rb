control 'SV-233319' do
  title 'Forescout must be configured so client machines do not communicate with other network devices in the DMZ or subnet except as needed to perform a client assessment or to identify itself. This is required for compliance with C2C Step 2.'
  desc 'Devices not compliant with DoD secure configuration policies are vulnerable to attack. Allowing these systems to connect presents a danger to the enclave.

Verify that Forescout  is not allowed to communicate with other hosts in the DMZ that do not perform security policy assessment or remediation services.'
  desc 'check', 'If DoD is not at C2C Step 2 or higher, this is not a finding.

1. Select Tools >> Options >> Appliance >> IP Assignment.
2. Select Segment >> IP Addresses. 
3. Verify the IP address for the DMZ subnet is not present.

If Forescout is not configured so the devices and servers in the Forescout solution (e.g., NAC, assessment server, policy decision point) do not communicate with other network devices in the DMZ or subnet except as needed to perform a remote access client assessment or to identify itself, this is a finding.'
  desc 'fix', 'Configure Forescout  to prevent communication with other hosts in the DMZ that do not perform security policy assessment or remediation services.

1. Log on to the Forescout UI. 
2. Select Tools >> Options >> Appliance >> IP Assignment.
3. Select Segment >> IP Addresses. Find the IP address for the DMZ subnet and delete it.'
  impact 0.5
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36514r811386_chk'
  tag severity: 'medium'
  tag gid: 'V-233319'
  tag rid: 'SV-233319r811387_rule'
  tag stig_id: 'FORE-NC-000110'
  tag gtitle: 'SRG-NET-000015-NAC-000130'
  tag fix_id: 'F-36479r605661_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
