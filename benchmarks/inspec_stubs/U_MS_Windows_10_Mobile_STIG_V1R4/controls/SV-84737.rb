control 'SV-84737' do
  title 'Windows 10 Mobile must generate audit records.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. They help identify attacks, so that breaches can either be prevented or limited in their scope. They facilitate analysis to improve performance and security. Auditable events include:

1. Start-up and shutdown of the audit functions;
2. All administrative actions;
3. Start-up and shutdown of the OS and kernel;
4. Insertion or removal of removable media;
5. Establishment of a synchronizing connection;
6. Specifically defined auditable events in Table 10 of MDF PP v.2.0.

SFR ID: FAU_GEN.1.1'
  desc 'check', 'Review Windows 10 Mobile configuration settings to determine if auditing is configured to generate audit records.

This validation procedure is performed only on the MDM administration console.

On the MDM administration console:

1. Ask the MDM administrator to verify the Security Auditing policy.
2. Find the setting for enabling auditing using the "Security Auditing".
3. Verify that setting configuration is turned on.

If the MDM does not have a compliance policy that enables "Security Auditing", this is a finding.'
  desc 'fix', 'Configure the MDM system to require the "Security Auditing" policy to be enabled for Windows 10 Mobile devices. 

Deploy the MDM policy on managed devices.'
  impact 0.3
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70591r1_chk'
  tag severity: 'low'
  tag gid: 'V-70115'
  tag rid: 'SV-84737r1_rule'
  tag stig_id: 'MSWM-10-203003'
  tag gtitle: 'PP-MDF-203001'
  tag fix_id: 'F-76351r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
