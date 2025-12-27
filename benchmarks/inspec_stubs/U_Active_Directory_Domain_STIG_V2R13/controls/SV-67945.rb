control 'SV-67945' do
  title 'Domain controllers must be blocked from Internet access.'
  desc 'Domain controllers provide access to highly privileged areas of a domain.  Such systems with Internet access may be exposed to numerous attacks and compromise the domain.  Restricting Internet access for domain controllers will aid in protecting these privileged areas from being compromised.'
  desc 'check', 'Verify domain controllers are blocked from Internet access.  Various methods may be employed to accomplish this, such as restrictions at boundary firewalls, through proxy services, host based firewalls or IPsec.

Review the Internet access restrictions with the administrator.  If Internet access is not prevented, this is a finding.

If a critical function requires Internet access, this must be documented and approved by the organization.'
  desc 'fix', 'Block domain controllers from internet access.  This can be accomplished with various methods, such as restrictions at boundary firewalls, proxy services, host based firewalls, or IPsec.   

If a critical function requires Internet access, this must be documented and approved by the organization.'
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-54679r1_chk'
  tag severity: 'medium'
  tag gid: 'V-53727'
  tag rid: 'SV-67945r1_rule'
  tag stig_id: 'AD.0015'
  tag gtitle: 'AD.0015'
  tag fix_id: 'F-58535r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
