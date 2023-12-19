control 'SV-4027' do
  title 'Servers do not employ Host Based Intrusion Detection (HIDS).'
  desc 'Servers without a HID may allow unauthorized access to go undetected and limit the ability of security personnel to stop malicious or unauthorized use of the device. In order to ensure that an attempted or existing attack goes unnoticed, the data from the HID must be monitored continuously.'
  desc 'check', 'Interview the IAO to determine if there is a process and policy in place to ensure Host Based IDS is installed on all servers. 

Work with the reviewers to determine compliance. 

**This check applies to Enhanced Compliance Validation visits.'
  desc 'fix', 'The IAO will ensure all servers employ HIDS, if technically feasible.  This requirement may not pertain to legacy systems and cutting edge devices that do not yet have the capability.   Documentation must exist from the vendor to approve any variance from this requirement.'
  impact 0.5
  ref 'DPMS Target DNS Policy'
  tag check_id: 'C-4321r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4027'
  tag rid: 'SV-4027r1_rule'
  tag stig_id: 'EN540'
  tag gtitle: 'Servers do not employ HIDs.'
  tag fix_id: 'F-3960r1_fix'
  tag responsibility: 'Information Assurance Officer'
end
