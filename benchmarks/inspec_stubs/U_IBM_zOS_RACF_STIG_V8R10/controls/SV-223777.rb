control 'SV-223777' do
  title 'IBM RACF must define UACC of NONE on all profiles.'
  desc 'The operating system must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.'
  desc 'check', 'Review all Dataset and resource profiles in the RACF database.

If any are not defined with UACC NONE, this is a finding.'
  desc 'fix', 'Define each dataset and resource profile with UACC(NONE)'
  impact 0.7
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25450r515019_chk'
  tag severity: 'high'
  tag gid: 'V-223777'
  tag rid: 'SV-223777r853619_rule'
  tag stig_id: 'RACF-OS-000210'
  tag gtitle: 'SRG-OS-000370-GPOS-00155'
  tag fix_id: 'F-25438r515020_fix'
  tag 'documentable'
  tag legacy: ['SV-107365', 'V-98261']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
