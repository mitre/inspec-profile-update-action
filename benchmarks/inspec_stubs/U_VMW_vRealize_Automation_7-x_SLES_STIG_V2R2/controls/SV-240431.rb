control 'SV-240431' do
  title 'NIS maps must be protected through hard-to-guess domain names.'
  desc 'The use of hard-to-guess NIS domain names provides additional protection from unauthorized access to the NIS directory information.'
  desc 'check', 'If the SLES for vRealize does not use NIS or NIS+, this is not applicable.

Check the domain name for NIS maps:

# domainname

If the name returned is simple to guess, such as the organization name, building or room name, etc., this is a finding.'
  desc 'fix', 'Change the NIS domain name to a value difficult to guess. Consult vendor documentation for the required procedure.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43664r671032_chk'
  tag severity: 'medium'
  tag gid: 'V-240431'
  tag rid: 'SV-240431r671034_rule'
  tag stig_id: 'VRAU-SL-000550'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-43623r671033_fix'
  tag 'documentable'
  tag legacy: ['SV-100289', 'V-89639']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
