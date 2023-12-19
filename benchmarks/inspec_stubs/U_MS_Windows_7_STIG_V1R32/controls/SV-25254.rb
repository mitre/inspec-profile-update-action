control 'SV-25254' do
  title 'Security-related software patches are not applied.'
  desc 'Major software vendors release security patches and hot fixes to their products when security vulnerabilities are discovered.  It is essential that these updates be applied in a timely manner to prevent unauthorized persons from exploiting identified vulnerabilities.

The severity code may be elevated to a Category I if patches deemed Critical have not been applied.'
  desc 'check', 'Verify that the site is applying all security-related patches released by Microsoft.  Determine the local site method for doing this (e.g., connection to a WSUS server, local procedure, etc.).

Severity Override: If any of the patches not installed are Microsoft ‘Critical’, then the category code should be elevated to ‘1’.

Note: If a penetration scan has been run on the network, it will report findings if security-related updates are not applied.  Then, this check may be marked as “Not Applicable”.

Some applications (such as DMS and GCSS) use a system release process to keep systems current. If this is the case, then these systems should be at the current release.'
  desc 'fix', 'Apply all Microsoft security-related patches to the Windows system.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-35r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3828'
  tag rid: 'SV-25254r1_rule'
  tag gtitle: 'Security-Related Software Patches'
  tag fix_id: 'F-63r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'If any of the patches not installed are Microsoft ‘Critical’, then this should be elevated to a Category 1.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
