control 'SV-96021' do
  title 'The Central Log Server must use multifactor authentication for network access to privileged user accounts.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased. 

Multifactor authentication requires using two or more factors to achieve authentication. 

Factors include: 
(i) something a user knows (e.g., password/PIN); 
(ii) something a user has (e.g., cryptographic identification device, token); or 
(iii) something a user is (e.g., biometric). 

A privileged account is defined as an information system account with authorizations of a privileged user. 

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the Internet).'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to require DoD PKI or another multifactor authentication method for logon via the network for all privileged accounts.  If the account of last resort is used for logon via the network (not recommended), then verify it is configured to require multifactor authentication method.

If the Central Log Server is not configured to use multifactor authentication for network access to privileged user accounts, this is a finding.'
  desc 'fix', 'This requirement applies to all privileged accounts used for access to the system via network access.

For systems where individual users access, configure and/or manage the system, configure the Central Log server application to use DoD PKI (preferred) or another multifactor authentication solution for network access to logon to the Central Log Server. If the account of last resort is used for logon via the network (not recommended), then configure the account to require multifactor authentication method.'
  impact 0.5
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-81007r3_chk'
  tag severity: 'medium'
  tag gid: 'V-81307'
  tag rid: 'SV-96021r1_rule'
  tag stig_id: 'SRG-APP-000149-AU-002280'
  tag gtitle: 'SRG-APP-000149-AU-002280'
  tag fix_id: 'F-88089r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000765']
  tag nist: ['IA-2 (1)']
end
