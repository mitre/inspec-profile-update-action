control 'SV-223768' do
  title 'IBM z/OS must employ a session manager to manage display of the Standard Mandatory DoD Notice and Consent Banner.'
  desc 'Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. All methods of gaining access to the system must comply with this requirement to assure that regulations are upheld.'
  desc 'check', 'Verify that any session manger in use displays the Standard Mandatory DoD Notice and Consent Banner before granting access to the system.

If the session manager does not display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system, this is a finding.'
  desc 'fix', 'Configure any session manger in use to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25441r514992_chk'
  tag severity: 'medium'
  tag gid: 'V-223768'
  tag rid: 'SV-223768r604139_rule'
  tag stig_id: 'RACF-OS-000120'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag fix_id: 'F-25429r514993_fix'
  tag 'documentable'
  tag legacy: ['SV-107347', 'V-98243']
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
