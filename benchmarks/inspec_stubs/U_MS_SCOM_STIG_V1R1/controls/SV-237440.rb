control 'SV-237440' do
  title 'A host-based firewall must be configured on the SCOM management servers.'
  desc 'To prevent a DDoS, a firewall that inspects and drops packets must be configured.'
  desc 'check', 'The steps in this check will vary based on the host-based firewall being used in the environment. 

For Windows Firewall, type wf.msc. 

Verify that the firewall is set to On. 

Click on Inbound rules and verify that there are no any-any allow rules in any profile. 

If McAfee is installed, it will be visible in the system tray. Verify with a McAfee administrator that there are no any-any rules allowing full access. 

If no host-based firewall is installed, or a host-based firewall is configured to allow all traffic inbound, this is a finding.'
  desc 'fix', "Configure a host-based firewall based on the organization's standards. A full list of ports needed for SCOM to function properly can be found here: https://docs.microsoft.com/en-us/system-center/scom/plan-security-config-firewall?view=sc-om-2019."
  impact 0.5
  ref 'DPMS Target Microsoft SCOM'
  tag check_id: 'C-40659r643964_chk'
  tag severity: 'medium'
  tag gid: 'V-237440'
  tag rid: 'SV-237440r643966_rule'
  tag stig_id: 'SCOM-SC-000002'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-40622r643965_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
