control 'SV-233315' do
  title 'Forescout appliance must not be configured to implement a DHCP layer 3 method for separation or device authorization. This is required for compliance with C2C Step 2.'
  desc 'An internal rogue device can still bypass the authentication process, regardless of the policy flow. Configuring the NAC to process all device authentication will ensure that any rogue device, internal or external, will be authenticated prior to network access.'
  desc 'check', 'If DOD is not at C2C Step 1 or higher, this is not a finding.

Check Forescout policy and verify it is configured to prohibit the use of DHCP to separate authenticated and nonauthenticated network access requests.

If the NAC does not prohibit the use of DHCP to separate authenticated and nonauthenticated network access requests, this is a finding.'
  desc 'fix', 'Log on to the Forescout UI.
 
1. Locate the Authentication & Authorization policy.
2. Ensure all traffic passing through the NAC is properly labeled and that all authenticated and nonauthenticated traffic goes through the NAC.'
  impact 0.7
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36510r919220_chk'
  tag severity: 'high'
  tag gid: 'V-233315'
  tag rid: 'SV-233315r919222_rule'
  tag stig_id: 'FORE-NC-000070'
  tag gtitle: 'SRG-NET-000015-NAC-000090'
  tag fix_id: 'F-36475r919221_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
