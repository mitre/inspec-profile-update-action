control 'SV-237813' do
  title 'The storage system in a hardened configuration must be configured to disable the Remote Copy feature, unless needed.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.'
  desc 'check', 'Verify the Remote Copy feature is not running via the following command:

cli% showrcopy
Remote Copy is not configured on this system.

Review the requirements by the Information Owner to determine whether the site requires the Remote Copy feature in order to meet mission objectives.

If the Status is "Started" and there is no documented requirement for this usage, this is a finding.

Any other response is not a finding.'
  desc 'fix', 'Determine whether Remote Copy operation was permitted under an exception.

If this feature was not permitted, then disable the Remote Copy feature with the following command:

cli% stoprcopy'
  impact 0.7
  ref 'DPMS Target HPE 3PAR StoreServ 3.2.x'
  tag check_id: 'C-41023r647846_chk'
  tag severity: 'high'
  tag gid: 'V-237813'
  tag rid: 'SV-237813r647848_rule'
  tag stig_id: 'HP3P-32-001001'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-40982r647847_fix'
  tag 'documentable'
  tag legacy: ['SV-85105', 'V-70483']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
