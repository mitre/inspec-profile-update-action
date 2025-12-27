control 'SV-79553' do
  title 'The DataPower Gateway must enforce approved authorizations for controlling the flow of management information within DataPower based on information flow control policies.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If management information flow is not enforced based on approved authorizations, the network device may become compromised. Information flow control regulates where management information is allowed to travel within a network device. The flow of all management information must be monitored and controlled so it does not introduce any unacceptable risk to the network device or data. 

Application-specific examples of enforcement occur in systems that employ rule sets or establish configuration settings that restrict information system services or message-filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of management information within the system in accordance with applicable policy.'
  desc 'check', 'Administration >> Access >> User Group >> Click the group to be confirmed >> Confirm that the access profiles are configured appropriately for the desired security policy. If the group profile(s) is/are not present, this is a finding

Privileged account user log on to default domain >> Administration >> Access >> RBM Settings >> Click "Credential Mapping" >> If Credential-mapping method is not "Local user group" or "Search LDAP for group name" is off, this is a finding.'
  desc 'fix', 'Create the appropriate User Group(s) using the "RBM Builder": Privileged account user log on to default domain >> Administration >> Access >> User Group >> Click the "Add" button >> Define the policy >> Click "Add" >> Click “Apply”.

Add users’ accounts to LDAP groups with the same names as those defined with the RBM Builder, in the remote Authentication/Authorization server (LDAP). Note: This takes place outside the context of the IBM DataPower Gateway. Specific instructions will depend on the LDAP server being used.

Configure Role-Based Management to use LDAP Group information during logon to map users to local group definitions.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65689r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65063'
  tag rid: 'SV-79553r1_rule'
  tag stig_id: 'WSDP-NM-000014'
  tag gtitle: 'SRG-APP-000038-NDM-000213'
  tag fix_id: 'F-71003r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
