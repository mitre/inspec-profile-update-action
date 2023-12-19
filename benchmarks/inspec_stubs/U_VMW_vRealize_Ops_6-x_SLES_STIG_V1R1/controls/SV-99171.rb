control 'SV-99171' do
  title 'NIS maps must be protected through hard-to-guess domain names.'
  desc 'The use of hard-to-guess NIS domain names provides additional protection from unauthorized access to the NIS directory information.'
  desc 'check', 'If SLES for vRealize does not use NIS or NIS+, this is not applicable.

Check the domain name for NIS maps:

# domainname

If the name returned is simple to guess, such as the organization name, building or room name, etc., this is a finding.'
  desc 'fix', 'Change the NIS domainname to a value difficult to guess. Consult vendor documentation for the required procedure.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88213r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88521'
  tag rid: 'SV-99171r1_rule'
  tag stig_id: 'VROM-SL-000530'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-95263r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
