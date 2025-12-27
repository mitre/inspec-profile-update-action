control 'SV-246845' do
  title 'The HYCU appliance must be running a release that is currently supported by the vendor.'
  desc 'Network devices running an unsupported operating system lack current security fixes required to mitigate the risks associated with recent vulnerabilities.'
  desc 'check', 'Verify that the HYCU device is running a supported version.

In the HYCU Web UI, on top bar in the right corner click on question mark icon >> About. The About menu shows the running version of HYCU.

If HYCU version is not on the list of supported versions, as specified in the End-of-Life Milestones and Dates, this is a finding.

Note: The HYCU support portal specifies the HYCU end of life policies. Visit https://www.hycu.com/wp-content/uploads/2017/03/HYCU-EOL-policy-Milestones-and-Dates.pdf to determine if the system is utilizing a supported version.'
  desc 'fix', 'Perform upgrade to the supported HYCU version following upgrade section of user manual.'
  impact 0.7
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50277r790583_chk'
  tag severity: 'high'
  tag gid: 'V-246845'
  tag rid: 'SV-246845r790585_rule'
  tag stig_id: 'HYCU-AU-000025'
  tag gtitle: 'SRG-APP-000516-NDM-000351'
  tag fix_id: 'F-50231r790584_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
