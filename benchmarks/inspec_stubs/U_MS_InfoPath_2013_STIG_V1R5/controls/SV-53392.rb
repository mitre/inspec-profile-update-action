control 'SV-53392' do
  title 'Disabling opening forms with managed code from the Internet security zone must be configured.'
  desc 'When InfoPath solutions are opened locally, the location of the form is checked so that updates to the form can be downloaded. If a user saves a form locally from a location on the Internet and then opens the same form from another location on the Internet, the cache will be updated with the new location information. If the user then opens the first form from its saved location, there will be a mismatch between the locally saved form and the locally cached form. This situation would typically happen when developers move forms to a new location, but if there is no warning when the cached location is used, it could be misused by an attacker attempting to redirect the forms to a new location. This type of attack is a form of beaconing. By default, if the location information in the cached form and the saved form to not match, the form cannot be opened without prompting the user for consent.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2013 -> Security "Disable opening forms with managed code from the Internet security zone" must be set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\InfoPath\\security

Criteria: If the value RunManagedCodeFromInternet is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2013 -> Security "Disable opening forms with managed code from the Internet security zone" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft InfoPath 2013'
  tag check_id: 'C-47633r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26620'
  tag rid: 'SV-53392r1_rule'
  tag stig_id: 'DTOO296'
  tag gtitle: 'DTOO296 - Managed code from the Internet'
  tag fix_id: 'F-46316r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
