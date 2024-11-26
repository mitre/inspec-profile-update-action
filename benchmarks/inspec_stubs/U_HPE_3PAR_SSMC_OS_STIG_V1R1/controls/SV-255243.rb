control 'SV-255243' do
  title 'SSMC must be configured to offload logs to a SIEM that is configured to alert the ISSO or SA when the local built-in admin account (ssmcadmin) is accessed.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DOD that reflects the most restrictive security posture consistent with operational requirements.

The ssmcadmin account is an emergency group account used to administer ssmc. This is a privileged account that can Log on to the SSMC appliance.

The ssmcaudit account is a nonprivileged group user account that can be enabled/disabled by ssmcadmin for CVE scanning via TUI. This is the other group account that can log on to the appliance.

By alerting to the use of ssmcadmin account, the information assurance team can mitigate the risks involved in using this group account. These alerts must be used to ensure that the use of this account is warranted and documented.'
  desc 'check', 'Verify that SSMC is configured to offload logs to a SIEM that is set up to alert the ISSO or SA when the ssmcadmin account is accessed by performing the following:

1. Log on to SIEM where the logs are being offloaded.

2. Log on to SSMC with the ssmcadmin account.

3. Return to the SIEM to see that an alert has been generated based on the access of the ssmcadmin account.

If the SIEM does not generate an alert for the ISSO or SA, this is a finding.'
  desc 'fix', 'Configure SSMC to offload logs to a SIEM that is set up to alert the ISSO or SA when the ssmcadmin account is accessed by performing the following:

1. Implement SSMC-WS-010080 to establish offloading logs to a SIEM.

2. Configure the SIEM to alert the ISSO or SA in the event that the ssmcadmin account is accessed.'
  impact 0.5
  ref 'DPMS Target HPE 3PAR SSMC OS'
  tag check_id: 'C-58856r869877_chk'
  tag severity: 'medium'
  tag gid: 'V-255243'
  tag rid: 'SV-255243r870274_rule'
  tag stig_id: 'SSMC-OS-010100'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-58800r869878_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
