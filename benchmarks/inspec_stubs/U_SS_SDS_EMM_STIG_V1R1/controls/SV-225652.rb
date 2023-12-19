control 'SV-225652' do
  title 'The firewall protecting the Samsung SDS EMM platform must be configured to restrict all network traffic to and from all addresses with the exception of ports, protocols, and IP address ranges required to support Samsung SDS EMM and platform functions.'
  desc 'Most information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations. Since Samsung SDS EMM is a critical component of the mobility architecture and must be configured to enable only those ports, protocols, and services (PPS) necessary to support functionality, all others must be expressly disabled or removed. A firewall installed on the Samsung SDS EMM provides a protection mechanism to ensure unwanted service requests do not reach the Samsung SDS EMM and outbound traffic is limited to only Samsung SDS EMM functionality.

SFR ID: FMT_SMF.1.1(2) b / CM-7 b

'
  desc 'check', 'Ask the MDM administrator for a list of ports, protocols, and IP address ranges necessary to support Samsung SDS EMM and platform functionality. A list can usually be found in the STIG Supplemental document or MDM product documentation.

Compare the list against the configuration of the firewall and identify discrepancies.

If the host-based firewall is not configured to support only ports, protocols, and IP address ranges necessary for operation, this is a finding.'
  desc 'fix', 'Configure the firewall on the Samsung SDS EMM to only permit ports, protocols, and IP address ranges necessary for operation.'
  impact 0.5
  ref 'DPMS Target Samsung SDS EMM'
  tag check_id: 'C-27353r547741_chk'
  tag severity: 'medium'
  tag gid: 'V-225652'
  tag rid: 'SV-225652r547743_rule'
  tag stig_id: 'SSDS-00-200020'
  tag gtitle: 'PP-MDM-431005'
  tag fix_id: 'F-27341r547742_fix'
  tag satisfies: ['SRG-APP-000142', 'PP-MDM-43100']
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
