control 'SV-31292' do
  title 'DCAF Console access must require a password to be entered by each user.'
  desc 'The DCAF Console enables an operator to access the ESCON Director Application remotely. Access to a DCAF Console by unauthorized personnel could result in varying of ESCON Directors online or offline and applying configuration changes. Unrestricted use by unauthorized personnel could lead to bypass of security, unlimited access to the system, and an altering of the environment. This would result in a loss of secure operations and will impact data operating integrity of the environment.  NOTE: Many newer installations no longer support the ESCON Director Application.  For installations not supporting the ESCON Director Application, this check is not applicable.'
  desc 'check', 'If the ESCON Director Application is present, have the System Administrator attempt to sign on to the DCAF Console and validate that a password is required, otherwise, this check is not applicable.

If sign-on access to the DCAF Console does not require a password this is a finding.'
  desc 'fix', 'Have the System Administrator review access authorization to DCAF Consoles. Ensure that all personnel are required to enter a password.

Remote access to the LAN may be provided through DCAF via a LAN or modem connection.
DCAF passwords should be implemented to prevent unauthorized access.'
  impact 0.5
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-31682r3_chk'
  tag severity: 'medium'
  tag gid: 'V-25247'
  tag rid: 'SV-31292r3_rule'
  tag stig_id: 'HLESC085'
  tag gtitle: 'HLESC085'
  tag fix_id: 'F-28169r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Systems Programmer']
  tag ia_controls: 'ECCD-1, IAIA-1, IAIA-2'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
