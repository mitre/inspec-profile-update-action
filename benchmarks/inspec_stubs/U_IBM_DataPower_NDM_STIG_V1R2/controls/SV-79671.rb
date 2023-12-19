control 'SV-79671' do
  title 'The DataPower Gateway must employ automated mechanisms to centrally verify authentication settings.'
  desc 'The use of authentication servers or other centralized management servers for providing centralized authentication services is required for network device management. Maintaining local administrator accounts for daily usage on each network device without centralized management is not scalable or feasible. Without centralized management, it is likely that credentials for some network devices will be forgotten, leading to delays in administration, which itself leads to delays in remediating production problems and in addressing compromises in a timely fashion.'
  desc 'check', 'Go to Administration >> Access >> RBM Settings. Verify Authentication Method is LDAP. If it is not, this is a finding.'
  desc 'fix', 'Go to Administration >> Access >> RBM Settings. Set Authentication Method to LDAP.

Configure LDAP connection as needed. The connection will be verified.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65809r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65181'
  tag rid: 'SV-79671r1_rule'
  tag stig_id: 'WSDP-NM-000136'
  tag gtitle: 'SRG-APP-000516-NDM-000338'
  tag fix_id: 'F-71121r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000372']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
