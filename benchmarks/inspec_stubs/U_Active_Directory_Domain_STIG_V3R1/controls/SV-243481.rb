control 'SV-243481' do
  title 'Access to need-to-know information must be restricted to an authorized community of interest.'
  desc 'Because trust relationships effectively eliminate a level of authentication in the trusting domain or forest, they represent less stringent access control at the domain or forest level in which the resource resides. To mitigate this risk, trust relationships must be documented so that they can be readily verified during periodic inspections designed to validate only approved trusts are configured in AD.'
  desc 'check', "1. Before performing this check, perform V-8530  which validates the trusts within the documentation are current within AD.

2. Obtain documentation of the site's approved trusts from the site representative.  

3. For each of the identified trusts, verify that the documentation includes a justification or explanation of the need-to-know basis of the trust. 

4. If the need for the trust is not documented, then this is a finding."
  desc 'fix', 'Delete the unneeded trust relationship or document the access requirement or mission need for the trust.'
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-46756r723476_chk'
  tag severity: 'medium'
  tag gid: 'V-243481'
  tag rid: 'SV-243481r723478_rule'
  tag stig_id: 'AD.0170'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-46713r723477_fix'
  tag 'documentable'
  tag legacy: ['V-8533', 'SV-9030']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
