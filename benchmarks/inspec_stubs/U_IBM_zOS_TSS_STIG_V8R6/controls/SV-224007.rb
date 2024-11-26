control 'SV-224007' do
  title 'IBM z/OS must not have Inaccessible APF libraries defined.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of non-essential capabilities include, but are not limited to, games, software packages, tools, and demonstration software, not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.'
  desc 'check', 'Refer to IEASYS00 member in SYS1.PARMLIB Concatenation. Determine proper APF and/or PROG member.
Examine each entry and verify that it exists on the specified volume. 

If inaccessible APF libraries exist, this is a finding.

ISRDDN APF'
  desc 'fix', 'Review the entire list of APF authorized libraries and remove those that are no longer valid designations.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25680r516420_chk'
  tag severity: 'medium'
  tag gid: 'V-224007'
  tag rid: 'SV-224007r561402_rule'
  tag stig_id: 'TSS0-OS-000110'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-25668r516421_fix'
  tag 'documentable'
  tag legacy: ['V-98723', 'SV-107827']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
