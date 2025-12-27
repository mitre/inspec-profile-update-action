control 'SV-233921' do
  title 'The Infoblox system must restrict the ability of individuals to use the DNS server to launch denial-of-Service (DoS) attacks against other information systems.'
  desc 'The Infoblox system must restrict the ability of individuals to use the DNS server to launch DoS attacks against other information systems.'
  desc 'check', 'Infoblox systems have a number of options that can be configured to reduce the ability to be exploited in a DoS attack. Primary consideration for this check should be given to client restrictions such as disabling open recursive servers, using Access Control Lists (ACLs) to limit client communication, and placement in secure network architecture to prevent address spoofing.

1. Navigate to Data Management >> DNS >> Grid DNS Properties.

2. For external authoritative name servers: 
a. Select the "Queries" tab. 
b. Verify the "Allow Recursion" check box is not enabled.

3. For internal name servers: 
a. On the "Updates" tab, verify that an ACL or Access Control Entry (ACE) for "Allow updates from" is enabled.
b. On the "Queries" tab, verify that either an ACL or ACE for "Allow queries from" is enabled.  

4. When complete, click "Cancel" to save the changes and exit the "Properties" screen.

If there is an open recursive DNS service on external name servers, or unrestricted access to internal name servers, this is a finding.'
  desc 'fix', '1. Navigate to Data Management >> DNS >> Grid DNS Properties. 
2. Select the "Queries" tab. 
3. For external authoritative name servers, disable "Allow Recursion" by clearing the check box.  
4. For internal name servers, on the "Updates" tab, configure either an ACL or ACE for "Allow updates from".  
5. On the "Queries" tab, configure either an ACL or ACE for "Allow queries from".  
6. When complete, click "Save & Close" to save the changes and exit the "Properties" screen. 
7. Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37106r611283_chk'
  tag severity: 'medium'
  tag gid: 'V-233921'
  tag rid: 'SV-233921r621666_rule'
  tag stig_id: 'IDNS-8X-700016'
  tag gtitle: 'SRG-APP-000246-DNS-000035'
  tag fix_id: 'F-37071r611284_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
