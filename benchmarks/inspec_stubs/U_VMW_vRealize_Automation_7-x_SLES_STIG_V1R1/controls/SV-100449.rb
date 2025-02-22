control 'SV-100449' do
  title 'The SLES for vRealize must audit the enforcement actions used to restrict access associated with changes to the system.'
  desc 'Without auditing the enforcement of access restrictions against changes to the application configuration, it will be difficult to identify attempted attacks and an audit trail will not be available for forensic investigation for after-the-fact actions.

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.'
  desc 'check', 'Verify the SLES for vRealize produces audit records by running the following command to determine the current status of the "auditd" service:

# service auditd status

If the service is enabled, the returned message must contain the following text:

Checking for service auditd                running

If the service is not "running", this is a finding.'
  desc 'fix', 'Enable the "auditd" service by performing the following commands:

# chkconfig auditd on
# service auditd start'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89491r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89799'
  tag rid: 'SV-100449r1_rule'
  tag stig_id: 'VRAU-SL-001165'
  tag gtitle: 'SRG-OS-000365-GPOS-00152'
  tag fix_id: 'F-96541r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
