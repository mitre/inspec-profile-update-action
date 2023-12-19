control 'SV-224009' do
  title 'IBM z/OS LNKAUTH=APFTAB must be specified in the IEASYSxx member(s) in the currently active parmlib data set(s).'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of non-essential capabilities include, but are not limited to, games, software packages, tools, and demonstration software, not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.'
  desc 'check', 'Refer to IEASYS00 member in SYS1.PARMLIB Concatenation.

If "LNKAUTH=APFTAB" is not specified, this is a finding.'
  desc 'fix', 'Configure LNKAUTH=APFTAB in the IEASYS00 member of PARMLIB.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25682r516426_chk'
  tag severity: 'medium'
  tag gid: 'V-224009'
  tag rid: 'SV-224009r877850_rule'
  tag stig_id: 'TSS0-OS-000130'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-25670r516427_fix'
  tag 'documentable'
  tag legacy: ['SV-107831', 'V-98727']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
