control 'SV-36489' do
  title 'The service account used to run the web service must have its password changed at least annually.'
  desc 'Normally, a service account is established for the web service to run under rather than permitting it to run as part of the local system. The password on such accounts must be changed at least annually. If the password is not changed periodically, the potential for a malicious party to gain access to the web services account is greatly enhanced.'
  desc 'check', 'Query the ISSO and confirm with the SA, the Web Manager, or the individual in an equivalent role.

Proposed Questions:

What is your policy for service account passwords? 
What types of services does this policy apply to? 
How often is service account passwords changed? 

If the web services password is not changed at least annually, this is a finding.'
  desc 'fix', 'Ensure that the service account ID used to run the web site has its password changed at least annually.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33732r2_chk'
  tag severity: 'medium'
  tag gid: 'V-2235'
  tag rid: 'SV-36489r3_rule'
  tag stig_id: 'WG060 W22'
  tag gtitle: 'WG060'
  tag fix_id: 'F-29367r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
end
