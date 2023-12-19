control 'SV-224673' do
  title 'The operating system must identify potentially security-relevant error conditions.'
  desc 'Security functional testing involves testing the operating system for conformance to the operating system security function specifications, as well as for the underlying security model. The need to verify security functionality applies to all security functions. The conformance criteria state the conditions necessary for the operating system to exhibit the desired security behavior or satisfy a security property. For example, successful login triggers an audit entry.'
  desc 'check', 'Ask the operator if DoD-approved SCAP compliance checking software is installed and run on a periodic basis.

If DoD-approved SCAP compliance checking software is not installed and/or not run on a periodic basis, this is a finding.'
  desc 'fix', 'Install, configure, and run DoD-approved SCAP compliance checking software on a periodic basis. Review the output of the software and document any out-of-compliance issues.'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-26362r462457_chk'
  tag severity: 'medium'
  tag gid: 'V-224673'
  tag rid: 'SV-224673r603268_rule'
  tag stig_id: 'SOL-11.1-090270'
  tag gtitle: 'SRG-OS-000445'
  tag fix_id: 'F-26350r462458_fix'
  tag 'documentable'
  tag legacy: ['V-47903', 'SV-60775']
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
end
