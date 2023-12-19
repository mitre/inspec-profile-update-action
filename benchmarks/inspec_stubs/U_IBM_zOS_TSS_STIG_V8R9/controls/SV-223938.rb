control 'SV-223938' do
  title 'The number of CA-TSS ACIDs with MISC9 authority must be justified.'
  desc 'Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS LIST(ACIDS) DATA(ADMIN) 

If the ACIDs having MISC9(ALL) or MISC9(CONSOLE) authority are designated SCAs who are responsible for the security for the domain this is not a finding.'
  desc 'fix', 'Review all ACIDs with the MISC9 attribute. Evaluate the impact of removing MISC9(ALL) or MISC9(CONSOLE) access from ACIDs not required to assign the CONSOLE attribute. It is suggested that MISC9(CONSOLE) assignment privileges be limited to the MSCA. Develop a plan of action and implement the changes.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25611r516213_chk'
  tag severity: 'medium'
  tag gid: 'V-223938'
  tag rid: 'SV-223938r877779_rule'
  tag stig_id: 'TSS0-ES-000650'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25599r516214_fix'
  tag 'documentable'
  tag legacy: ['SV-107687', 'V-98583']
  tag cci: ['CCI-000366', 'CCI-002145']
  tag nist: ['CM-6 b', 'AC-2 (11)']
end
