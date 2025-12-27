control 'SV-223786' do
  title 'IBM z/OS LNKAUTH=APFTAB must be specified in the IEASYSxx member(s) in the currently active parmlib data set(s).'
  desc 'Failure to specify LINKAUTH=APFTAB allows libraries other than those designated as APF to contain authorized modules which could bypass security and violate the integrity of the operating system environment. This expanded authorization list inhibits the ability to control inclusion of these modules.'
  desc 'check', 'Refer to IEASYS00 member in SYS1.PARMLIB Concatenation.

If LNKAUTH=APFTAB is not specified, this is a finding.'
  desc 'fix', 'Configure LNKAUTH=APFTAB in the IEASYS00 member of PARMLIB.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25459r515046_chk'
  tag severity: 'medium'
  tag gid: 'V-223786'
  tag rid: 'SV-223786r604139_rule'
  tag stig_id: 'RACF-OS-000300'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-25447r515047_fix'
  tag 'documentable'
  tag legacy: ['V-98279', 'SV-107383']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
