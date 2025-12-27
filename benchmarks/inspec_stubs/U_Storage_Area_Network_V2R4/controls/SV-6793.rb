control 'SV-6793' do
  title 'The SAN fabric zoning lists are not based on a policy of Deny-by-Default with blocks on all services and protocols not required on the given port or by the site.'
  desc 'By using the Deny-by-Default based policy, any service or protocol not required by a port and overlooked in the zoning list will be denied access.  If Deny-by-Default based policy was not used any overlooked service or protocol not required by a port could have access to sensitive data compromising that data.
The IAO/NSO will ensure that SAN fabric zoning lists are based on a policy of Deny-by-Default with blocks on all services and protocols not required on the given port or by the site.'
  desc 'check', 'The reviewer will, with the assistance of the IAO/NSO, verify that SAN fabric zoning lists are based on a policy of Deny-by-Default with blocks on all services and protocols not required on the given port or by the site.'
  desc 'fix', 'Develop a plan to identify all services and protocols needed by each port in the SAN, modify the routing lists to enforce a Deny-by-Default policy and allow only the identified services and protocols on each port that requires them.  Obtain CM approval for the plan and implement the plan.'
  impact 0.7
  ref 'DPMS Target SANS Storage Device'
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2573r1_chk'
  tag severity: 'high'
  tag gid: 'V-6647'
  tag rid: 'SV-6793r1_rule'
  tag stig_id: 'SAN04.019.00'
  tag gtitle: 'SAN Fabric Zoning List Deny-By-Default'
  tag fix_id: 'F-6250r1_fix'
  tag 'documentable'
  tag potential_impacts: 'Changing to a policy based on Deny-by-Default can cause overlooked services or protocols required by a port to be denied access to data they need.'
  tag responsibility: ['Information Assurance Officer', 'Network Security Officer']
  tag ia_controls: 'DCBP-1'
end
