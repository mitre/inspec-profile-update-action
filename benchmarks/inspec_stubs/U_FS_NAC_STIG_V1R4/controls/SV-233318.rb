control 'SV-233318' do
  title 'Forescout must place client machines on a blacklist or terminate network communications on devices when critical security issues are found that put the network at risk. This is required for compliance with C2C Step 4.'
  desc 'Devices that are found to have critical security issues place the network at risk if they are allowed to continue communications. Policy actions should be in place to terminate or restrict network communication or place the suspicious machine on a blacklist.'
  desc 'check', 'If DoD is not at C2C Step 4 or higher, this is not a finding.

Check Forescout policy to ensure that any device with a critical security issue is checked through a security policy and an action is taken to either blacklist it or terminate communication with other network devices.

If the NAC does not immediately place the device on the blacklist and terminate the connection when critical security issues are found that put the network at immediate risk, this a finding.'
  desc 'fix', 'Use the Forescout Administrator UI to configure compliance policies to ensure any device with critical security issues is added to a blacklist, had its network communication blocked, or isolated from trusted network traffic for remediation. 
 
1. From the Policy tab, identify a Compliance policy.
2. Within the Compliance policy, under Sub-Rule for a device with critical security issues, ensure that an action that Adds Device to Blacklist and/or Disables Device is enabled.

If Forescout does not place client machines on a blacklist or terminate network communications on devices when critical security issues are found that put the network at risk, this is a finding.'
  impact 0.7
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36513r811384_chk'
  tag severity: 'high'
  tag gid: 'V-233318'
  tag rid: 'SV-233318r811385_rule'
  tag stig_id: 'FORE-NC-000100'
  tag gtitle: 'SRG-NET-000015-NAC-000120'
  tag fix_id: 'F-36478r803461_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
