control 'SV-221601' do
  title 'Splunk Enterprise must use organization level authentication to uniquely identify and authenticate users.'
  desc 'To ensure accountability and prevent unauthenticated access, organizational users must be uniquely identified and authenticated to prevent potential misuse and compromise of the system. 

Sharing of accounts prevents accountability and non-repudiation. Organizational users must be uniquely identified and authenticated for all accesses. The use of an organizational level authentication mechanism provides centralized management of accounts, and provides many benefits not normally leveraged by local account mechanisms.'
  desc 'check', 'If the instance being checked is in a distributed environment and has the web interface disabled, this check is N/A.

Select Settings >> Access Controls >> Authentication method.

Verify that LDAP or SAML is selected.

If LDAP or SAML is not selected, this is a finding.'
  desc 'fix', 'Select Settings >> Access Controls >> Authentication method.

If using LDAP for user accounts:
Select LDAP and create an LDAP strategy with the proper settings to connect to the LDAP server.
Map the appropriate LDAP groups to the appropriate Splunk roles for proper user access.

If using SAML for user accounts:
Select SAML and create an SAML strategy with the proper settings to connect to the SAML provider.
Map the appropriate SAML groups to the appropriate Splunk roles for proper user access.'
  impact 0.7
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23316r663925_chk'
  tag severity: 'high'
  tag gid: 'V-221601'
  tag rid: 'SV-221601r879589_rule'
  tag stig_id: 'SPLK-CL-000020'
  tag gtitle: 'SRG-APP-000148-AU-002270'
  tag fix_id: 'F-23305r416261_fix'
  tag 'documentable'
  tag legacy: ['SV-111307', 'V-102351']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
