control 'SV-237915' do
  title 'IBM z/VM must be configured to disable non-essential capabilities.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of non-essential capabilities include, but are not limited to, games, software packages, tools, and demonstration software, not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.'
  desc 'check', 'Determine if the System administrator has a documented manual process to review and disable non-essential capabilities for z/VM.

If there is no policy and process to review and disable non-essential capabilities, this is a finding.

If capabilities identified in the policy are not disabled, this is a finding.'
  desc 'fix', 'Develop a policy for a procedure to review and disable non-essential capabilities for z/VM.

Ensure that all identified non-essential capabilities are disabled.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41125r649583_chk'
  tag severity: 'medium'
  tag gid: 'V-237915'
  tag rid: 'SV-237915r649585_rule'
  tag stig_id: 'IBMZ-VM-000560'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-41084r649584_fix'
  tag 'documentable'
  tag legacy: ['SV-93583', 'V-78877']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
