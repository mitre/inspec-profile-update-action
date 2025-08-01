control 'SV-25949' do
  title 'The system must enforce the entire password during authentication.'
  desc "Some common password hashing schemes only process the first eight characters of a user's password, which reduces the effective strength of the password."
  desc 'check', "Determine if the system enforces the correctness of the entire password during authentication. If it does not, this is a finding.

Procedure:
Set an account's password to a string longer than 8 characters. Attempt to log into the account using only the first 8 characters of the password. If the login succeeds, this is a finding."
  desc 'fix', 'Configure the system to enforce the correctness of the entire password during authentication. Consult vendor documentation for the required settings.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29093r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22302'
  tag rid: 'SV-25949r1_rule'
  tag stig_id: 'GEN000585'
  tag gtitle: 'GEN000585'
  tag fix_id: 'F-26092r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
