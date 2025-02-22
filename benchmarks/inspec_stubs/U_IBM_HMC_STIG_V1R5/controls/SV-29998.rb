control 'SV-29998' do
  title 'The Distributed Console Access Facility (DCAF) Console must be restricted to only authorized personnel.'
  desc 'The DCAF Console enables an operator to access the ESCON Director Application remotely. Access to a DCAF Console by unauthorized personnel could result in varying of ESCON Directors online or offline and applying configuration changes. Unrestricted use by unauthorized personnel could lead to bypass of security, unlimited access to the system, and an altering of the environment. This would result in a loss of secure operations and will impact data operating integrity of the environment.  NOTE: Many newer installations no longer support the ESCON Director Application.  For installations not supporting the ESCON Director Application, this check is not applicable.'
  desc 'check', 'If the ESCON Director Application is present, verify that sign-on access to the DCAF Console is restricted to authorized personnel, otherwise, this check is not applicable.

If sign-on access to the DCAF Console is not restricted, this is a finding.'
  desc 'fix', 'Review access authorization to DCAF Consoles. Ensure that all personnel are restricted to authorized levels of access.

Remote access to the LAN may be provided through DCAF via a LAN or modem connection.
DCAF passwords should be implemented to prevent unauthorized access.'
  impact 0.5
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-679r3_chk'
  tag severity: 'medium'
  tag gid: 'V-24344'
  tag rid: 'SV-29998r3_rule'
  tag stig_id: 'HLESC080'
  tag gtitle: 'HLESC080'
  tag fix_id: 'F-2361r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager', 'Security Manager', 'Systems Programmer']
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-002227', 'CCI-002235']
  tag nist: ['AC-6 (5)', 'AC-6 (10)']
end
