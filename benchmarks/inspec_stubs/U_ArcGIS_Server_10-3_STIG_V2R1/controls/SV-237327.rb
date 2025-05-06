control 'SV-237327' do
  title 'The ArcGIS Server must implement replay-resistant authentication mechanisms for network access to privileged accounts and non-privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. 

A privileged account is any information system account with authorizations of a privileged user.

A non-privileged account is any operating system account with authorizations of a non-privileged user.

'
  desc 'check', 'Review the ArcGIS for Server configuration to ensure that the application implements replay-resistant authentication mechanisms for network access to privileged accounts. Substitute the target environment’s values for [bracketed] variables.

Within IIS >> within the [“arcgis”] application >> Authentication >> Verify that “Windows Authentication” is “Enabled”.
Verify that “Anonymous Authentication” is “Disabled”.
If “Windows Authentication” is not enabled, or “Anonymous Authentication” is enabled, this is a finding.

Within IIS >> within the [“arcgis”] application >> Authentication >> Select “Windows Authentication” >> “Providers”.
Verify “Negotiate” or “Negotate:Kerberos” are at the top of the list, with NTLM at the bottom of the list.
If “NTLM” is at the top of the “Providers” list, this is a finding.

This control is not applicable for ArcGIS Server deployments configured to allow anonymous access.

This control is not applicable for ArcGIS Server deployments which are integrated with and protected by one or more third party DoD compliant certificate authentication solutions.'
  desc 'fix', 'Configure ArcGIS for Server to utilize replay-resistant authentication mechanisms for network access to privileged accounts. Substitute the target environment’s values for [bracketed] variables.

Enable Active Directory Client Certificate Authentication "To map client certificates by using Active Directory mapping."'
  impact 0.5
  ref 'DPMS Target ArcGIS for Server 10-3'
  tag check_id: 'C-40546r642798_chk'
  tag severity: 'medium'
  tag gid: 'V-237327'
  tag rid: 'SV-237327r879597_rule'
  tag stig_id: 'AGIS-00-000062'
  tag gtitle: 'SRG-APP-000156'
  tag fix_id: 'F-40509r642799_fix'
  tag satisfies: ['SRG-APP-000156', 'SRG-APP-000157', 'SRG-APP-000295']
  tag 'documentable'
  tag legacy: ['SV-79919', 'V-65429']
  tag cci: ['CCI-001941', 'CCI-001942', 'CCI-002361']
  tag nist: ['IA-2 (8)', 'IA-2 (9)', 'AC-12']
end
