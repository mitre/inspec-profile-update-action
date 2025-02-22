control 'SV-99331' do
  title 'The SLES for vRealize must notify designated personnel if baseline configurations are changed in an unauthorized manner.'
  desc 'Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the SLES for vRealize. SLES for vRealize’s IMO/ISSO and SAs must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item.'
  desc 'check', 'Verify SLES for vRealize produces audit records by running the following command to determine the current status of the "auditd" service:

# service auditd status

If the service is enabled, the returned message must contain the following text:

Checking for service auditd                running

If the service is not running, this is a finding.'
  desc 'fix', 'Enable the "auditd" service by performing the following commands:

# chkconfig auditd on
# service auditd start'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88373r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88681'
  tag rid: 'SV-99331r1_rule'
  tag stig_id: 'VROM-SL-001130'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-95423r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end
